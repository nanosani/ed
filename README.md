# ed
Email Deliverability Check Plugin for WordPress

# 📧 Email Domain Health Checker – WordPress Plugin

**Email Domain Health Checker** is a robust WordPress plugin that helps you verify and validate your domain’s email configurations. It performs real-time checks on MX, SPF, DKIM, DMARC, MTA-STS, BIMI records, and blacklist status to ensure proper email deliverability and domain security.

---

## ✅ Why Use Email Domain Health Checker?

- 🔒 Prevent Email Spoofing
- 📬 Improve Email Deliverability
- 🛡 Protect Sender Reputation
- 🧠 Understand and Fix DNS Misconfigurations
- 🌍 Monitor Domain Health Across Nameservers

---

## 🚀 Features

### 🔍 Core Validation

- **MX Records** – Validate mail server configuration and priority
- **SPF Records** – Check authorized sending servers
- **DKIM Records** – Validate digital signature setup
- **DMARC Records** – Analyze policy, reporting, and alignment
- **MTA-STS** – Enforce email encryption policies
- **BIMI** – Confirm branding support and logo setup
- **Email Blacklist Check** – Detect domain blacklisting
- **IP Blacklist Check** – Detect blacklisted sending IPs

### 📊 Advanced Tools

- Real-time DNS lookups
- Color-coded visual status indicators (green/yellow/red)
- Best practice suggestions and configuration tips
- Support for DKIM selectors
- Result consistency check across multiple nameservers
- Expandable sections for each DNS category

---

## 🧩 Installation

1. Download the `email-domain-health-checker.zip` file.
2. Go to **Plugins > Add New** in your WordPress Admin.
3. Upload the ZIP and click **Install Now**.
4. Activate the plugin via the **Plugins** menu.
5. Use shortcode `[edhsc]` to embed the checker anywhere.

---

## 📋 Shortcode Options

Use `[edhsc]` with the following parameters:

| Attribute           | Description |
|---------------------|-------------|
| `default_domain`    | Pre-fills the domain field |
| `show_sections`     | Comma-separated list (e.g. `mx,spf,dkim`) |
| `theme`             | `light`, `dark`, or `auto` |
| `result_display`    | `accordion`, `tabs`, or `full` |
| `button_text`       | Custom scan button label |
| `placeholder_text`  | Custom placeholder for domain input |
| `hide_input`        | `true` to hide domain input field |

---

## 📘 How to Use

1. Add `[edhsc]` shortcode to any page/post.
2. Enter a domain (e.g. `yourdomain.com`).
3. Optionally, enter a DKIM selector (e.g. `default`, `google`).
4. Click **Scan** to analyze DNS and email records.
5. Expand result sections to view raw data, pass/fail status, and suggestions.

---

## 🛠 Troubleshooting

- **Scan Button Not Working?**
  - Check browser console for errors
  - Ensure PHP functions like `dns_get_record()` are enabled
  - Confirm WordPress version is 5.0+
- **Inconsistent Results?**
  - Wait for DNS propagation (24–48 hrs after changes)
  - Clear cache (DNS/browser)
- **Missing DKIM Selector?**
  - Try known values: `default`, `google`, `selector1`
- **Too Many SPF Lookups?**
  - Simplify includes and remove unused mechanisms
- **No DMARC Reports Received?**
  - Validate `rua`/`ruf` tags and email domains

---

## 📅 Changelog

### v1.0.0
- Initial release
- Support for MX, SPF, DKIM, DMARC, MTA-STS, BIMI
- Email and IP blacklist checks
- Shortcode support with customization

---

## 🧭 Roadmap

- ✅ Basic DNS + blacklist scanning
- ⏳ PDF report export
- ⏳ Email alerts and scheduled scans
- ⏳ API integrations (e.g., Google Workspace, Microsoft 365)
- ⏳ Bulk domain scanning
- ⏳ Custom validation rules
- ⏳ Record generators (MX, SPF, DKIM, etc.)
- ⏳ TLS-RPT support

---

## 💡 Use Cases

- ✅ Webmasters checking email configuration
- ✅ Agencies auditing clients’ DNS records
- ✅ Email marketers improving deliverability
- ✅ Developers troubleshooting sending issues
- ✅ Anyone securing email communications

---

## 💬 Support

Having trouble or need help?

📧 [Contact Us](https://yourpluginwebsite.com/contact)  
📘 [Documentation](https://yourpluginwebsite.com/docs)  
🎯 [View Demo](https://yourpluginwebsite.com/demo)

---

## 📝 License

Licensed under [GPL v2 or later](https://www.gnu.org/licenses/gpl-2.0.html).

---

## 🙌 Credits

- Based on RFC standards for SPF, DKIM, DMARC, MTA-STS, and BIMI.
- Uses public DNS libraries and blacklist APIs.
- Built with ❤️ by [Your Team or Developer Name].
