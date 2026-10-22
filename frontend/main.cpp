#include <QApplication>
#include <QClipboard>
#include <QCommandLineParser>
#include <QDateTime>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QFileInfo>
#include <QFormLayout>
#include <QFutureWatcher>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QJsonDocument>
#include <QJsonObject>
#include <QKeySequence>
#include <QLabel>
#include <QLineEdit>
#include <QMainWindow>
#include <QPlainTextEdit>
#include <QPixmap>
#include <QPushButton>
#include <QRegularExpression>
#include <QShortcut>
#include <QSignalBlocker>
#include <QStatusBar>
#include <QTimer>
#include <QVBoxLayout>
#include <QtConcurrent/QtConcurrentRun>

#include "authorization_policy.h"
#include "cardguard_ffi.h"

#include <array>
#include <atomic>
#include <cmath>
#include <cstring>
#include <memory>
#include <utility>

namespace {
constexpr qsizetype MaxTokenBytes = 4096;
constexpr qsizetype MaxRequestBytes = 16 * 1024;
constexpr qsizetype MaxResponseBytes = 64 * 1024;
constexpr int RequestTimeoutMs = 8000;

std::atomic<bool> verifierTaskRunning{false};

// The worker owns this reservation even if its window has already been destroyed.
class VerifierReservation final
{
public:
    VerifierReservation()
    {
        bool expected = false;
        acquired_ = verifierTaskRunning.compare_exchange_strong(expected, true);
    }

    ~VerifierReservation()
    {
        if (acquired_)
            verifierTaskRunning.store(false);
    }

    bool acquired() const { return acquired_; }

private:
    bool acquired_ = false;
};

QByteArray requestFromRust(const QByteArray &request)
{
    std::array<uint8_t, static_cast<size_t>(MaxResponseBytes)> output{};
    const size_t written = cardguard_request(
        reinterpret_cast<const uint8_t *>(request.constData()),
        static_cast<size_t>(request.size()), output.data(), output.size());
    if (written == 0 || written > output.size())
        return {};
    return QByteArray(reinterpret_cast<const char *>(output.data()),
                      static_cast<qsizetype>(written));
}

QLabel *label(const QString &text, const QString &objectName = {})
{
    auto *widget = new QLabel(text);
    widget->setTextFormat(Qt::PlainText);
    widget->setObjectName(objectName);
    return widget;
}

bool validUnixSeconds(const QJsonValue &value)
{
    if (!value.isDouble())
        return false;
    const double seconds = value.toDouble();
    return std::isfinite(seconds) && seconds > 0.0 && seconds < 253402300800.0
        && std::floor(seconds) == seconds;
}

class MainWindow final : public QMainWindow
{
public:
    explicit MainWindow(bool smokeTest, bool smokeVerify, const QString &smokeToken,
                        const QString &screenshotPath)
        : smokeTest_(smokeTest), smokeVerify_(smokeVerify), smokeToken_(smokeToken),
          screenshotPath_(screenshotPath)
    {
        setWindowTitle(QStringLiteral("CardGuard · 授权校验"));
        setMinimumSize(560, 480);
        resize(700, 520);

        auto *central = new QWidget;
        setCentralWidget(central);
        auto *outer = new QVBoxLayout(central);

        auto *deviceGroup = new QGroupBox(QStringLiteral("设备信息"));
        auto *deviceForm = new QFormLayout(deviceGroup);
        auto *deviceRow = new QHBoxLayout;
        device_ = new QLineEdit;
        device_->setReadOnly(true);
        device_->setPlaceholderText(QStringLiteral("正在读取本机身份…"));
        device_->setObjectName(QStringLiteral("device"));
        device_->setAccessibleName(QStringLiteral("本机机器码"));
        deviceRow->addWidget(device_, 1);
        retry_ = new QPushButton(QStringLiteral("刷新"));
        copy_ = new QPushButton(QStringLiteral("复制"));
        copy_->setEnabled(false);
        deviceRow->addWidget(retry_);
        deviceRow->addWidget(copy_);
        deviceForm->addRow(QStringLiteral("机器码："), deviceRow);
        deviceNote_ = label(QStringLiteral("仅在本地计算设备身份"));
        deviceForm->addRow(QString(), deviceNote_);
        outer->addWidget(deviceGroup);

        auto *tokenGroup = new QGroupBox(QStringLiteral("授权卡密"));
        auto *tokenLayout = new QVBoxLayout(tokenGroup);
        token_ = new QPlainTextEdit;
        token_->setObjectName(QStringLiteral("token"));
        token_->setPlaceholderText(QStringLiteral("请输入或粘贴完整授权卡密"));
        token_->setAccessibleName(QStringLiteral("授权卡密输入框"));
        token_->setTabChangesFocus(true);
        token_->setMinimumHeight(100);
        token_->setMaximumHeight(120);
        tokenLayout->addWidget(token_);
        inputHint_ = label(QStringLiteral("卡密仅在本机校验，不写入日志或配置。"));
        inputHint_->setWordWrap(true);
        tokenLayout->addWidget(inputHint_);
        auto *tokenActions = new QHBoxLayout;
        paste_ = new QPushButton(QStringLiteral("粘贴"));
        clear_ = new QPushButton(QStringLiteral("清空"));
        verify_ = new QPushButton(QStringLiteral("校验"));
        const QKeySequence verifySequence(Qt::CTRL | Qt::Key_Return);
        verify_->setToolTip(QStringLiteral("校验授权卡密（%1）")
                                .arg(verifySequence.toString(QKeySequence::NativeText)));
        verify_->setEnabled(false);
        tokenActions->addStretch();
        tokenActions->addWidget(paste_);
        tokenActions->addWidget(clear_);
        tokenActions->addWidget(verify_);
        tokenLayout->addLayout(tokenActions);
        outer->addWidget(tokenGroup);

        auto *resultGroup = new QGroupBox(QStringLiteral("校验结果"));
        auto *result = new QFormLayout(resultGroup);
        result->setFieldGrowthPolicy(QFormLayout::AllNonFixedFieldsGrow);
        status_ = label(QStringLiteral("未授权"), QStringLiteral("status"));
        result->addRow(QStringLiteral("状态："), status_);
        addResultField(result, QStringLiteral("授权对象"), subject_);
        addResultField(result, QStringLiteral("授权编号"), licenseId_);
        addResultField(result, QStringLiteral("有效期至"), expires_);
        detail_ = label(QStringLiteral("请输入卡密并校验。"));
        detail_->setWordWrap(true);
        result->addRow(QStringLiteral("说明："), detail_);
        outer->addWidget(resultGroup);
        outer->addStretch();
        statusBar()->showMessage(QStringLiteral("等待授权凭证"));

        connect(copy_, &QPushButton::clicked, this, [this] {
            QApplication::clipboard()->setText(device_->text());
            deviceNote_->setText(QStringLiteral("机器码已复制"));
        });
        connect(retry_, &QPushButton::clicked, this, [this] { requestDevice(); });
        connect(paste_, &QPushButton::clicked, this, [this] {
            const QString text = QApplication::clipboard()->text().trimmed();
            if (text.toUtf8().size() > MaxTokenBytes) {
                fail(QStringLiteral("卡密长度超出限制"), QStringLiteral("请粘贴不超过 4096 字节的完整授权卡密。"));
                return;
            }
            token_->setPlainText(text);
        });
        connect(clear_, &QPushButton::clicked, token_, &QPlainTextEdit::clear);
        connect(token_, &QPlainTextEdit::textChanged, this, [this] {
            resetLicense();
            setStatus(QStringLiteral("neutral"), QStringLiteral("未授权"), QStringLiteral("等待授权校验"),
                      QStringLiteral("卡密已更改，请点击验证授权。"));
            const bool tooLong = token_->toPlainText().toUtf8().size() > MaxTokenBytes;
            inputHint_->setText(tooLong ? QStringLiteral("卡密超出 4096 字节限制，请检查粘贴内容。")
                                       : QStringLiteral("卡密仅在本机校验，不写入日志或配置。"));
            updateControls();
        });
        connect(verify_, &QPushButton::clicked, this, [this] { verifyLicense(); });
        auto *verifyShortcut = new QShortcut(verifySequence, this);
        connect(verifyShortcut, &QShortcut::activated, this, [this] {
            if (verify_->isEnabled())
                verifyLicense();
        });
        timeout_.setSingleShot(true);
        connect(&timeout_, &QTimer::timeout, this, [this] {
            if (request_ != Request::None)
                finishFailure(QStringLiteral("授权校验超时"), QStringLiteral("本次结果已作废，正在等待后台任务结束；任务结束后可重试。"));
        });
        expiryTimer_.setInterval(1000);
        connect(&expiryTimer_, &QTimer::timeout, this, [this] {
            if (verifiedExpiry_ <= 0)
                return;
            const qint64 now = QDateTime::currentSecsSinceEpoch();
            if (now < verifiedIssuedAt_) {
                fail(QStringLiteral("系统时间异常"), QStringLiteral("当前系统时间早于授权签发时间，请校正时间后重新校验。"));
            } else if (now >= verifiedExpiry_ || verifiedElapsed_.elapsed() >= verifiedRemainingMs_) {
                fail(QStringLiteral("授权已过期"), QStringLiteral("授权有效期已结束，请联系签发方更新卡密。"));
            }
        });
        expiryTimer_.start();
        QTimer::singleShot(0, this, [this] { requestDevice(); });
    }

    ~MainWindow() override
    {
        timeout_.stop();
        ++requestGeneration_;
        if (watcher_)
            watcher_->disconnect(this);
        // QFutureWatcher destruction does not cancel the call. The worker captures
        // only owned buffers/reservation, and never reads this window or its widgets.
    }

private:
    enum class Request { None, Device, Verify };

    static void addResultField(QFormLayout *layout, const QString &title, QLabel *&value)
    {
        value = label(QStringLiteral("—"), QStringLiteral("fieldValue"));
        value->setWordWrap(true);
        value->setTextInteractionFlags(Qt::TextSelectableByMouse);
        layout->addRow(title + QStringLiteral("："), value);
    }

    void updateControls()
    {
        const bool idle = request_ == Request::None && watcher_ == nullptr;
        const QByteArray bytes = token_->toPlainText().trimmed().toUtf8();
        verify_->setEnabled(idle && !device_->text().isEmpty() && !bytes.isEmpty()
                            && bytes.size() <= MaxTokenBytes);
        verify_->setText(request_ == Request::Verify ? QStringLiteral("正在校验…") : QStringLiteral("校验"));
        retry_->setEnabled(idle);
        copy_->setEnabled(idle && !device_->text().isEmpty());
        paste_->setEnabled(idle);
        clear_->setEnabled(idle);
        token_->setReadOnly(!idle);
    }

    void resetLicense()
    {
        verifiedExpiry_ = 0;
        verifiedIssuedAt_ = 0;
        verifiedRemainingMs_ = 0;
        verifiedElapsed_.invalidate();
        subject_->setText(QStringLiteral("—"));
        licenseId_->setText(QStringLiteral("—"));
        expires_->setText(QStringLiteral("—"));
    }

    void setStatus(const QString &state, const QString &badge, const QString &title, const QString &description)
    {
        Q_UNUSED(state);
        status_->setText(badge);
        detail_->setText(description);
        statusBar()->showMessage(title);
    }

    void fail(const QString &title, const QString &description)
    {
        resetLicense();
        setStatus(QStringLiteral("invalid"), QStringLiteral("授权无效"), title, description);
    }

    void requestDevice()
    {
        if (request_ != Request::None || watcher_ != nullptr)
            return;
        resetLicense();
        device_->clear();
        device_->setPlaceholderText(QStringLiteral("正在读取本机身份…"));
        deviceNote_->setText(QStringLiteral("正在读取设备身份"));
        setStatus(QStringLiteral("neutral"), QStringLiteral("未授权"), QStringLiteral("等待授权凭证"),
                  QStringLiteral("请在设备身份读取完成后校验授权卡密。"));
        startRequest(Request::Device, QJsonObject{{QStringLiteral("op"), QStringLiteral("device")}});
    }

    void verifyLicense()
    {
        if (!verify_->isEnabled())
            return;
        resetLicense();
        setStatus(QStringLiteral("pending"), QStringLiteral("校验中"), QStringLiteral("正在检查授权"),
                  QStringLiteral("校验签名、设备绑定与授权期限…"));
        startRequest(Request::Verify,
                     QJsonObject{{QStringLiteral("op"), QStringLiteral("verify")},
                                 {QStringLiteral("token"), token_->toPlainText().trimmed()}});
    }

    void startRequest(Request kind, const QJsonObject &payload)
    {
        if (request_ != Request::None || watcher_ != nullptr)
            return;
        QByteArray encoded = QJsonDocument(payload).toJson(QJsonDocument::Compact);
        if (encoded.isEmpty() || encoded.size() > MaxRequestBytes) {
            finishResponseFailure(kind, QStringLiteral("校验请求无效"), QStringLiteral("请求内容超出安全限制，授权未通过。"));
            return;
        }
        auto reservation = std::make_shared<VerifierReservation>();
        if (!reservation->acquired()) {
            finishResponseFailure(kind, QStringLiteral("后台校验仍在运行"), QStringLiteral("请等待当前任务结束后重新读取设备身份。"));
            return;
        }
        request_ = kind;
        const quint64 generation = ++requestGeneration_;
        auto *watcher = new QFutureWatcher<QByteArray>(this);
        watcher_ = watcher;
        updateControls();
        connect(watcher, &QFutureWatcher<QByteArray>::finished, this,
                [this, watcher, generation, kind] {
            if (watcher != watcher_)
                return;
            const QFuture<QByteArray> completed = watcher->future();
            watcher_ = nullptr;
            watcher->deleteLater();
            timeout_.stop();
            request_ = Request::None;
            updateControls();
            // A timeout invalidates this generation, but keeps the single worker
            // occupied until it actually finishes. Its late result never grants access.
            if (generation != requestGeneration_)
                return;
            QByteArray response;
            try {
                response = completed.result();
            } catch (...) {
                finishResponseFailure(kind, QStringLiteral("授权校验执行失败"), QStringLiteral("校验未能正常完成，请重试。"));
                return;
            }
            if (response.isEmpty() || response.size() > MaxResponseBytes) {
                finishResponseFailure(kind, QStringLiteral("校验结果异常"), QStringLiteral("本机校验返回了无效数据，授权未通过。"));
                return;
            }
            handleResponse(kind, response);
        });
        timeout_.start(RequestTimeoutMs);
        try {
            watcher->setFuture(QtConcurrent::run(
                [encoded = std::move(encoded), reservation = std::move(reservation)]() mutable {
                    // Release before Qt reports completion, including exception unwinding.
                    [[maybe_unused]] auto running = std::move(reservation);
                    return requestFromRust(encoded);
                }));
        } catch (...) {
            watcher_ = nullptr;
            watcher->disconnect(this);
            watcher->deleteLater();
            finishFailure(QStringLiteral("无法启动授权校验"), QStringLiteral("后台任务未能启动，授权未通过。"));
        }
    }

    void finishFailure(const QString &title, const QString &description)
    {
        const Request kind = request_;
        ++requestGeneration_;
        timeout_.stop();
        request_ = Request::None;
        finishResponseFailure(kind, title, description);
    }

    void finishResponseFailure(Request kind, const QString &title, const QString &description)
    {
        fail(title, description);
        if (kind == Request::Device) {
            device_->clear();
            device_->setPlaceholderText(QStringLiteral("设备身份不可用"));
            deviceNote_->setText(QStringLiteral("读取失败，请重试"));
        }
        updateControls();
        finishSmokeTest(kind, false);
    }

    void handleResponse(Request kind, const QByteArray &bytes)
    {
        QJsonParseError parseError;
        const QJsonDocument document = QJsonDocument::fromJson(bytes.trimmed(), &parseError);
        if (parseError.error != QJsonParseError::NoError || !document.isObject()) {
            finishResponseFailure(kind, QStringLiteral("校验组件响应格式错误"), QStringLiteral("无法识别组件返回的数据，授权未通过。"));
            return;
        }
        const QJsonObject object = document.object();
        if (!object.value(QStringLiteral("ok")).isBool()) {
            finishResponseFailure(kind, QStringLiteral("校验组件响应格式错误"), QStringLiteral("组件返回了不完整的校验结果。"));
            return;
        }
        if (!object.value(QStringLiteral("ok")).toBool()) {
            const QJsonObject error = object.value(QStringLiteral("error")).toObject();
            QString message = error.value(QStringLiteral("message")).toString().left(240);
            if (message.isEmpty())
                message = QStringLiteral("授权校验未通过，请检查卡密、设备与有效期。" );
            finishResponseFailure(kind, kind == Request::Device ? QStringLiteral("无法读取设备身份") : QStringLiteral("授权校验未通过"), message);
            return;
        }
        const QJsonObject result = object.value(QStringLiteral("result")).toObject();
        const QString deviceId = result.value(QStringLiteral("device_id")).toString();
        static const QRegularExpression devicePattern(QStringLiteral("^[0-9a-f]{64}$"));
        if (!devicePattern.match(deviceId).hasMatch()) {
            finishResponseFailure(kind, QStringLiteral("校验结果不完整"), QStringLiteral("设备身份格式异常，授权未通过。"));
            return;
        }
        if (kind == Request::Device) {
            device_->setText(deviceId);
            device_->setCursorPosition(0);
            device_->setToolTip(deviceId);
            deviceNote_->setText(QStringLiteral("设备身份已就绪"));
            updateControls();
            finishSmokeTest(kind, true);
            return;
        }
        const QString subject = result.value(QStringLiteral("subject")).toString();
        const QString licenseId = result.value(QStringLiteral("license_id")).toString();
        if (kind != Request::Verify || subject.isEmpty() || subject.size() > 512 || licenseId.isEmpty()
            || licenseId.size() > 256 || deviceId != device_->text()
            || result.value(QStringLiteral("product")).toString() != QStringLiteral("card-demo")
            || result.value(QStringLiteral("version")).toInt(-1) != 1
            || !validUnixSeconds(result.value(QStringLiteral("issued_at")))
            || !validUnixSeconds(result.value(QStringLiteral("expires_at")))) {
            finishResponseFailure(kind, QStringLiteral("校验结果不完整"), QStringLiteral("授权信息与当前设备或产品不一致。"));
            return;
        }
        const qint64 expiresAt = static_cast<qint64>(result.value(QStringLiteral("expires_at")).toDouble());
        const qint64 issuedAt = static_cast<qint64>(result.value(QStringLiteral("issued_at")).toDouble());
        const qint64 now = QDateTime::currentSecsSinceEpoch();
        if (expiresAt <= now || issuedAt > now || issuedAt >= expiresAt) {
            finishResponseFailure(kind, QStringLiteral("授权期限无效"), QStringLiteral("授权尚未生效或已经过期。"));
            return;
        }
        const uint32_t checks =
            (object.value(QStringLiteral("ok")).toBool() ? CARDGUARD_CHECK_RUST_VALID : 0u)
            | (result.value(QStringLiteral("version")).toInt(-1) == 1 ? CARDGUARD_CHECK_VERSION : 0u)
            | (result.value(QStringLiteral("product")).toString() == QStringLiteral("card-demo") ? CARDGUARD_CHECK_PRODUCT : 0u)
            | (deviceId == device_->text() ? CARDGUARD_CHECK_DEVICE : 0u)
            | CARDGUARD_CHECK_FIELDS; // All required fields/types passed the checks above.
        if (cardguard_policy_allows(checks, static_cast<uint64_t>(issuedAt),
                                   static_cast<uint64_t>(expiresAt), static_cast<uint64_t>(now)) != 1) {
            finishResponseFailure(kind, QStringLiteral("授权策略校验未通过"), QStringLiteral("授权范围或有效期限不符合当前产品要求。"));
            return;
        }
        verifiedExpiry_ = expiresAt;
        verifiedIssuedAt_ = issuedAt;
        verifiedRemainingMs_ = (expiresAt - now) * 1000;
        verifiedElapsed_.start();
        subject_->setText(subject);
        licenseId_->setText(licenseId);
        expires_->setText(QDateTime::fromSecsSinceEpoch(expiresAt).toLocalTime().toString(QStringLiteral("yyyy-MM-dd HH:mm:ss")));
        expires_->setToolTip(QStringLiteral("以本机时区显示"));
        setStatus(QStringLiteral("valid"), QStringLiteral("授权有效"), QStringLiteral("已通过本机授权校验"),
                  QStringLiteral("签名、设备绑定、产品与有效期检查均已通过。"));
        finishSmokeTest(kind, true);
    }

    void finishSmokeTest(Request kind, bool success)
    {
        if (!smokeTest_)
            return;
        if (kind == Request::Device && success && smokeVerify_) {
            QTimer::singleShot(0, this, [this] {
                token_->setPlainText(smokeToken_);
                smokeToken_.clear();
                verifyLicense();
            });
            return;
        }
        QTimer::singleShot(100, this, [this, success] {
            if (!screenshotPath_.isEmpty()) {
                // Verification has finished. Keep credentials out of test artifacts.
                const QSignalBlocker tokenSignals(token_);
                const QSignalBlocker deviceSignals(device_);
                token_->setPlainText(QStringLiteral("[授权卡密已隐藏]"));
                device_->setText(QStringLiteral("[机器码已隐藏]"));
                if (!grab().save(screenshotPath_, "PNG")) {
                    QCoreApplication::exit(4);
                    return;
                }
            }
            QCoreApplication::exit(success ? 0 : 2);
        });
    }

    bool smokeTest_ = false;
    bool smokeVerify_ = false;
    QString smokeToken_;
    QString screenshotPath_;
    Request request_ = Request::None;
    QFutureWatcher<QByteArray> *watcher_ = nullptr;
    quint64 requestGeneration_ = 0;
    QTimer timeout_;
    QTimer expiryTimer_;
    qint64 verifiedExpiry_ = 0;
    qint64 verifiedIssuedAt_ = 0;
    qint64 verifiedRemainingMs_ = 0;
    QElapsedTimer verifiedElapsed_;
    QLineEdit *device_ = nullptr;
    QPlainTextEdit *token_ = nullptr;
    QPushButton *verify_ = nullptr;
    QPushButton *retry_ = nullptr;
    QPushButton *copy_ = nullptr;
    QPushButton *paste_ = nullptr;
    QPushButton *clear_ = nullptr;
    QLabel *deviceNote_ = nullptr;
    QLabel *inputHint_ = nullptr;
    QLabel *status_ = nullptr;
    QLabel *detail_ = nullptr;
    QLabel *subject_ = nullptr;
    QLabel *licenseId_ = nullptr;
    QLabel *expires_ = nullptr;
};
} // namespace

int main(int argc, char *argv[])
{
    if (argc == 2 && std::strcmp(argv[1], "--stdio") == 0)
        return cardguard_run_stdio();

    bool smokeTest = false;
    for (int i = 1; i < argc; ++i)
        smokeTest = smokeTest || QByteArray(argv[i]) == "--smoke-test";
    if (smokeTest && qEnvironmentVariableIsEmpty("QT_QPA_PLATFORM"))
        qputenv("QT_QPA_PLATFORM", "offscreen");
#ifdef Q_OS_WIN
    // The offscreen plugin does not discover Windows fonts automatically.
    if (smokeTest && qEnvironmentVariable("QT_QPA_PLATFORM") == QStringLiteral("offscreen")
        && qEnvironmentVariableIsEmpty("QT_QPA_FONTDIR")) {
        const QString fonts = QDir(qEnvironmentVariable("WINDIR", QStringLiteral("C:/Windows")))
                                  .absoluteFilePath(QStringLiteral("Fonts"));
        if (QFileInfo(fonts).isDir())
            qputenv("QT_QPA_FONTDIR", fonts.toUtf8());
    }
#endif
    QApplication app(argc, argv);
    app.setApplicationName(QStringLiteral("CardGuard"));
    app.setApplicationVersion(QStringLiteral("0.1.0"));
    app.setOrganizationName(QStringLiteral("CardGuard Demo"));
    QCommandLineParser parser;
    parser.setApplicationDescription(QStringLiteral("CardGuard 本机授权校验演示"));
    parser.addHelpOption();
    parser.addVersionOption();
    parser.addOption({QStringLiteral("smoke-test"), QStringLiteral("使用 offscreen 运行设备读取回归测试。")});
    parser.addOption({QStringLiteral("smoke-token-file"), QStringLiteral("仅测试模式：读取卡密并完成真实授权校验。"), QStringLiteral("absolute-path")});
    parser.addOption({QStringLiteral("screenshot"), QStringLiteral("仅测试模式：退出前保存窗口 PNG。"), QStringLiteral("absolute-path")});
    parser.process(app);
    const bool smokeVerify = parser.isSet(QStringLiteral("smoke-token-file"));
    const QString tokenPath = parser.value(QStringLiteral("smoke-token-file"));
    const QString screenshotPath = parser.value(QStringLiteral("screenshot"));
    if ((!smokeTest && (smokeVerify || parser.isSet(QStringLiteral("screenshot"))))
        || (smokeVerify && !QFileInfo(tokenPath).isAbsolute())
        || (parser.isSet(QStringLiteral("screenshot")) && !QFileInfo(screenshotPath).isAbsolute()))
        return 2;
    QString smokeToken;
    if (smokeVerify) {
        QFile file(tokenPath);
        if (!file.open(QIODevice::ReadOnly))
            return 2;
        const QByteArray bytes = file.read(MaxTokenBytes + 5);
        smokeToken = QString::fromUtf8(bytes).trimmed();
        if (!file.atEnd() || smokeToken.isEmpty() || smokeToken.toUtf8().size() > MaxTokenBytes)
            return 2;
    }
    MainWindow window(smokeTest, smokeVerify, smokeToken, screenshotPath);
    window.show();
    if (smokeTest)
        QTimer::singleShot((smokeVerify ? 2 : 1) * RequestTimeoutMs + 1500,
                           &app, [] { QCoreApplication::exit(3); });
    return app.exec();
}
