using System;
using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using WebMoney.Cryptography;
using WebMoney.KeyExtractor.Properties;
using WebMoney.KeyExtractor.Utils;
using System.IO;
using System.Web;
using System.Diagnostics;
using Org.BouncyCastle.Crypto;

namespace WebMoney.KeyExtractor
{
    sealed partial class MainForm : Form
    {
        //const int HelpIndex = 2001;
        private readonly CultureInfo _enCulture; // для английского языка
        private readonly CultureInfo _ruCulture; // для русского языка

        private CultureInfo _curCulture; // текущая культура

        private object _content;

        // ключ v2: сид подписи Ed25519, 32 байта
        private sealed class V2SignKey
        {
            public V2SignKey(byte[] seed)
            {
                Seed = seed;
            }

            public byte[] Seed { get; private set; }
        }

        public MainForm()
        {
            // инициализируем readonly поля
            _enCulture = new CultureInfo("en-US");
            _ruCulture = new CultureInfo("ru-RU");
            // восстанавливаем культуру из settings
            _curCulture = LocalizableUtils.LoadCulture();
            // применяем текущую культуру к рабочему потоку
            Thread.CurrentThread.CurrentCulture = _curCulture;
            Thread.CurrentThread.CurrentUICulture = _curCulture;

            InitializeComponent();
        }

        private void MainForm_Load(object sender, EventArgs e)
        {
            // устанавливаем флажек языка
            SetLangSwitcher();
            // устанавливаем название
            Text = AssemblyInfoAccessors.AssemblyTitleShortVersion;
            // устанавливаем статус по умолчанию
            infoStatusLabel.Text = Resources.Done;
        }

        private void wMKeeperClassicToolStripMenuItem_Click(object sender, EventArgs e)
        {
            openFileDialog.Filter = @"WM keys' file|*.kwm";

            if (DialogResult.OK != openFileDialog.ShowDialog(this))
                return;

            byte[] encrypted;

            try
            {
                encrypted = File.ReadAllBytes(openFileDialog.FileName);
            }
            catch (IOException)
            {
                MessageBox.Show(this, Resources.FailedOpenFile, Resources.Error, MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            if (0 == encrypted.Length)
            {
                MessageBox.Show(this, Resources.WrongData, Resources.Error, MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            // версия формата читается без пароля: у классического файла по этому смещению ноль
            var isV2 = V2KeyFile.FileSize == encrypted.Length &&
                       V2KeyFile.Version == V2KeyFile.ReadVersion(encrypted);

            object content;

            using (var ipForm = new IdPasswordForm())
            {
                if (DialogResult.OK != ipForm.ShowDialog(this))
                    return;

                try
                {
                    if (isV2)
                    {
                        // WMID входит в additional data шифра строкой из 12 цифр
                        var wmid = ipForm.Id.ToString("D12", CultureInfo.InvariantCulture);
                        var keys = V2KeyFile.Load(encrypted, wmid, ipForm.Password);
                        // ключ обмена утилите не нужен
                        Array.Clear(keys.ExchangeKey, 0, keys.ExchangeKey.Length);
                        content = new V2SignKey(keys.SignSeed);
                    }
                    else
                    {
                        content = DecryptedKey.Decrypt(encrypted, ipForm.Id,
                                                       Encoding.GetEncoding(1251).GetBytes(ipForm.Password));
                    }
                }
                catch (CryptographicException exception)
                {
                    ShowWrongData(exception);
                    return;
                }
                catch (CryptoException exception)
                {
                    // v2: неверный WMID или пароль валят проверку тега Poly1305
                    ShowWrongData(exception);
                    return;
                }
                catch (ArgumentException exception)
                {
                    // v2: заголовок файла не соответствует формату
                    ShowWrongData(exception);
                    return;
                }
            }

            _content = content;

            ToEnabled();
            signStringToolStripMenuItem.Enabled = true;
            SetText();
            SendText(Resources.FileOpened);
        }

        private void wMLightToolStripMenuItem_Click(object sender, EventArgs e)
        {
            openFileDialog.Filter = @"Personal Information Exchange|*.pfx";

            if (DialogResult.OK != openFileDialog.ShowDialog(this))
                return;

            byte[] content;

            using (var pForm = new PasswordForm())
            {

                if (DialogResult.OK != pForm.ShowDialog(this))
                    return;

                try
                {
                    var certificate =
                        new X509Certificate2(openFileDialog.FileName, pForm.Password,
                                             X509KeyStorageFlags.Exportable);

                    content = certificate.Export(X509ContentType.Pfx, string.Empty);
                }
                catch (CryptographicException)
                {
                    MessageBox.Show(this, Resources.WrongData, Resources.Error, MessageBoxButtons.OK,
                                    MessageBoxIcon.Error);
                    return;
                }
            }

            _content = content;

            ToEnabled();
            signStringToolStripMenuItem.Enabled = false;
            SetText();
            SendText(Resources.FileOpened);
        }

        private void wMRootCertificateToolStripMenuItem_Click(object sender, EventArgs e)
        {
            openFileDialog.Filter = @"Security Certificate|*.crt;*.cer";

            if (DialogResult.OK != openFileDialog.ShowDialog(this))
                return;

            byte[] content;

            try
            {
                var certificate = new X509Certificate(openFileDialog.FileName);
                content = certificate.Export(X509ContentType.Cert);
            }
            catch (CryptographicException)
            {
                MessageBox.Show(this, Resources.WrongData, Resources.Error, MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            _content = content;

            ToEnabled();
            signStringToolStripMenuItem.Enabled = false;
            SetText();
            SendText(Resources.FileOpened);
        }

        private void exitToolStripMenuItem_Click(object sender, EventArgs e)
        {
            Close();
        }

        private void copyToolStripMenuItem_Click(object sender, EventArgs e)
        {
            CopyText();
        }

        private void base64ToolStripMenuItem_Click(object sender, EventArgs e)
        {
            base64ToolStripMenuItem.Checked = true;
            base64XmlToolStripMenuItem.Checked = false;
            hexToolStripMenuItem.Checked = false;
            hexStringToolStripMenuItem.Checked = false;

            SetText();
        }

        private void base64XmlToolStripMenuItem_Click(object sender, EventArgs e)
        {
            base64ToolStripMenuItem.Checked = false;
            base64XmlToolStripMenuItem.Checked = true;
            hexToolStripMenuItem.Checked = false;
            hexStringToolStripMenuItem.Checked = false;

            SetText();
        }

        private void hexToolStripMenuItem_Click(object sender, EventArgs e)
        {
            base64ToolStripMenuItem.Checked = false;
            base64XmlToolStripMenuItem.Checked = false;
            hexToolStripMenuItem.Checked = true;
            hexStringToolStripMenuItem.Checked = false;

            SetText();
        }

        private void hexStringToolStripMenuItem_Click(object sender, EventArgs e)
        {
            base64ToolStripMenuItem.Checked = false;
            base64XmlToolStripMenuItem.Checked = false;
            hexToolStripMenuItem.Checked = false;
            hexStringToolStripMenuItem.Checked = true;

            SetText();
        }

        private void md4HashToolStripMenuItem_Click(object sender, EventArgs e)
        {
            (new ComputeForm(mD4HashToolStripMenuItem.Text, MD4Hash.GetHashString)).Show();
        }

        private void md5HashToolStripMenuItem_Click(object sender, EventArgs e)
        {
            (new ComputeForm(mD5HashToolStripMenuItem.Text, MD5Hash.GetHashString)).Show();
        }

        private void sha1HashToolStripMenuItem_Click(object sender, EventArgs e)
        {
            (new ComputeForm(sHA1HashToolStripMenuItem.Text, SHA1Hash.GetHashString)).Show();
        }

        private void signStringToolStripMenuItem_Click(object sender, EventArgs e)
        {
            var signer = new Signer();

            var v2SignKey = _content as V2SignKey;

            if (null != v2SignKey)
                signer.Initialize(v2SignKey.Seed);
            else
                signer.Initialize((KeeperKey)_content);

            (new ComputeForm(signStringToolStripMenuItem.Text, signer.Sign)).Show();
        }

        private void englishToolStripMenuItem_Click(object sender, EventArgs e)
        {
            // устанавливаем английский язык
            _curCulture = _enCulture;
            SetCulture();
            SendText(Resources.LanguageChanged);
        }

        private void russianToolStripMenuItem_Click(object sender, EventArgs e)
        {
            // устанавливаем русский язык
            _curCulture = _ruCulture;
            SetCulture();
            SendText(Resources.LanguageChanged);
        }

        private void aboutToolStripMenuItem_Click(object sender, EventArgs e)
        {
            new AboutForm().ShowDialog(this);
        }

        private void helpTopicsToolStripMenuItem_Click(object sender, EventArgs e)
        {
            //Help.ShowHelp(this, Resources.HelpFile, HelpNavigator.TopicId, HelpIndex.ToString(NumberFormatInfo.InvariantInfo));

            Process.Start("https://ru.webmoney.wiki/projects/webmoney/wiki/WMSignerFX");
            SendText(Resources.HelpContentsOpened);
        }

        private void copyButton_Click(object sender, EventArgs e)
        {
            CopyText();
        }

        private void exitButton_Click(object sender, EventArgs e)
        {
            Close();
        }

        private void SendText(string text)
        {
            mainTimer.Enabled = false;
            infoStatusLabel.Text = text;
            mainTimer.Enabled = true;
        }

        private void mainTimer_Tick(object sender, EventArgs e)
        {
            mainTimer.Enabled = false;
            infoStatusLabel.Text = Resources.Done;
        }

        private void ToEnabled()
        {
            resultGroupBox.Enabled = true;
            copyToolStripMenuItem.Enabled = true;
            copyButton.Enabled = true;

            base64ToolStripMenuItem.Enabled = true;
            base64XmlToolStripMenuItem.Enabled = true;
            hexToolStripMenuItem.Enabled = true;
            hexStringToolStripMenuItem.Enabled = true;
        }

        private void SetText()
        {
            if (_content is KeeperKey)
            {
                var keeperKey = (KeeperKey)_content;

                if (base64ToolStripMenuItem.Checked)
                {
                    resultTextBox.Text = keeperKey.ToXmlString();
                }
                else if (base64XmlToolStripMenuItem.Checked)
                {
                    resultTextBox.Text = HttpUtility.HtmlEncode(keeperKey.ToXmlString());
                }
                else if (hexToolStripMenuItem.Checked)
                {
                    const string template = "byte[] modulus = new byte[]{{{0}}};\r\nbyte[] d = new byte[] {{{1}}};";

                    resultTextBox.Text = string.Format(CultureInfo.InvariantCulture, template,
                                                       "0x" +
                                                       BitConverter.ToString(keeperKey.Modulus).Replace("-", ", 0x"),
                                                       "0x" +
                                                       BitConverter.ToString(keeperKey.D).Replace("-", ", 0x"));
                }
                else if (hexStringToolStripMenuItem.Checked)
                {
                    // D и N: 16-битные слова, младшее первым, каждое как %04x
                    resultTextBox.Text = "D: " + ComHex.ToComHex(keeperKey.D) + "\r\n" +
                                         "N: " + ComHex.ToComHex(keeperKey.Modulus);
                }
            }
            else if (_content is V2SignKey)
            {
                var seed = ((V2SignKey)_content).Seed;

                if (base64ToolStripMenuItem.Checked)
                {
                    // как у RSA: XML, который принимает Signer.Initialize(string)
                    resultTextBox.Text = Signer.ToV2XmlString(seed);
                }
                else if (base64XmlToolStripMenuItem.Checked)
                {
                    resultTextBox.Text = HttpUtility.HtmlEncode(Signer.ToV2XmlString(seed));
                }
                else if (hexToolStripMenuItem.Checked)
                {
                    const string template = "byte[] seed = new byte[] {{{0}}};";

                    resultTextBox.Text = string.Format(CultureInfo.InvariantCulture, template,
                                                       "0x" + BitConverter.ToString(seed).Replace("-", ", 0x"));
                }
                else if (hexStringToolStripMenuItem.Checked)
                {
                    // форма хранения сида v2: 64 hex, побайтово
                    resultTextBox.Text = BitConverter.ToString(seed).Replace("-", string.Empty)
                        .ToLowerInvariant();
                }
            }
            else if (_content is byte[])
            {
                var result = (byte[])_content;

                if (base64ToolStripMenuItem.Checked || base64XmlToolStripMenuItem.Checked)
                {
                    resultTextBox.Text = Convert.ToBase64String(result);
                }
                else if (hexToolStripMenuItem.Checked)
                {
                    resultTextBox.Text = @"0x" + BitConverter.ToString(result).Replace("-", ", 0x");
                }
                else if (hexStringToolStripMenuItem.Checked)
                {
                    resultTextBox.Text = BitConverter.ToString(result).Replace("-", string.Empty)
                        .ToLowerInvariant();
                }
            }
        }

        private void ShowWrongData(Exception exception)
        {
            var message = string.Format(CultureInfo.InvariantCulture, "{0}: {1}", Resources.WrongData,
                                        exception.Message);

            MessageBox.Show(this, message, Resources.Error, MessageBoxButtons.OK, MessageBoxIcon.Error);
        }

        private void SetCulture()
        {
            Thread.CurrentThread.CurrentCulture = _curCulture;
            Thread.CurrentThread.CurrentUICulture = _curCulture;

            LocalizableUtils.TranslateFormTo(this);

            LocalizableUtils.SaveCulture(_curCulture);

            // устанавливаем флажек языка
            SetLangSwitcher();

            // устанавливаем название
            Text = AssemblyInfoAccessors.AssemblyTitleShortVersion;
        }

        private void SetLangSwitcher()
        {
            switch (_curCulture.ToString())
            {
                case "ru-RU":
                    englishToolStripMenuItem.Checked = false;
                    russianToolStripMenuItem.Checked = true;
                    break;
                default:
                    russianToolStripMenuItem.Checked = false;
                    englishToolStripMenuItem.Checked = true;
                    break;
            }
        }

        private void CopyText()
        {
            Clipboard.Clear();

            if (string.IsNullOrEmpty(resultTextBox.Text))
                return;

            Clipboard.SetText(resultTextBox.Text);
            SendText(Resources.TextCopiedClipboard);
        }
    }
}