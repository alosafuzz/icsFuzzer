# Security Policy

## Authorized Use Only

icsFuzzer is a security research and assessment tool designed for use by
authorized security professionals. Unauthorized use against systems you do not
have explicit written permission to test is illegal and may result in criminal
prosecution under the Computer Fraud and Abuse Act (CFAA), the UK Computer
Misuse Act, and equivalent laws in other jurisdictions.

## Safe Testing Guidelines

Before running icsFuzzer in any environment:

1. **Obtain written authorization** from the system/facility owner
2. **Coordinate with plant operators** — inform them of the test window and
   which systems will be targeted
3. **Use a test/lab environment** whenever possible rather than production
4. **Start with a single non-critical device** before expanding scope
5. **Have a rollback plan** — know how to restore affected devices
6. **Use `--delay`** to throttle packet rates on sensitive network segments
7. **Monitor target devices** for unexpected behavior during testing

## Responsible Disclosure

If icsFuzzer identifies a vulnerability in a vendor's ICS product:

1. **Do not publish** vulnerability details before coordinating with the vendor
2. Contact the vendor's security disclosure team directly, or use:
   - **ICS-CERT:** https://www.cisa.gov/report
   - **CERT/CC:** https://kb.cert.org/vuls/report/
3. Provide a 90-day remediation window before public disclosure

## Contact

For vulnerability reports related to icsFuzzer itself or findings made with
this tool, contact: **alosafuzz@proton.me**

## Good Faith Research

This tool is released in good faith for the purpose of improving the security
of industrial control systems. Users are expected to act responsibly and in
accordance with applicable laws and their organization's policies.
