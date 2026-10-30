# CDN-Installer

[English](README.md) · [Русский](README.ru.md)

**A VPN that looks like an ordinary website from the outside.**

One command on your server's console — a wizard then asks a few questions and installs everything itself.

> This project targets Russian users circumventing local internet restrictions, so the full documentation is written in Russian. See [README.ru.md](README.ru.md) for the complete setup guide.

## What it does

The script sets up a VPN on your server (VLESS on the Xray engine) and hides it behind a Russian CDN — the same kind of network that serves video, maps and images for major sites. A phone opens an HTTPS connection to an address like `cdn12.gslb.example.ru`, indistinguishable from the traffic it already generates browsing social media. Blocking such addresses outright is hard, since they're shared by sites everyone uses.

## Requirements

- A VPS running Ubuntu 22.04 / 24.04 or Debian, with `root` access
- At least 5 GB of free disk space
- A domain with DNS access
- A Yandex Cloud account (used to create the CDN resource)

## Getting Started

Run the installer on a clean server — it rewrites nginx configuration, installs Docker and enables the `ufw` firewall with a deny-by-default policy. See [README.ru.md](README.ru.md) for the full step-by-step installation, CDN setup, flags and troubleshooting.

## License

[MIT](LICENSE) — copy, modify and embed it anywhere, including in commercial projects. The one condition is keeping the license text and attribution.
