# The Infrastructure Threat

## What's happening

Windows computers are being turned into cell phone infrastructure.

Carriers, device manufacturers, and government programs are pushing mobile-network components onto desktop Windows:

- **Cellular services** running on desktops with no cellular hardware
- **eSIM provisioning** on machines that will never have a SIM
- **MDM enrollment** giving organizations remote control over personal PCs
- **Carrier bloatware** with permissions to read your location, messages, and contacts
- **Phone Link bridges** exfiltrating notifications, photos, and messages

## Why it matters

Your desktop is not a cell tower. It is not a phone. When mobile infrastructure runs on your PC:

1. Your computer answers to the carrier, not to you
2. Location data flows through cellular stacks you didn't ask for
3. MDM gives someone else an off switch for your machine
4. Every layer is another attack surface

## What Falsum does

The **Infrastructure Detector** finds all of it:

- Scans for cellular/mobile services
- Checks for MDM enrollment
- Finds carrier bloatware
- Detects Phone Link bridges
- Checks for eSIM provisioning

If your desktop is running phone software, Falsum tells you in plain language what's there, why it shouldn't be, and what to do about it.

## The principle

Your computer serves you. Not the carrier. Not the manufacturer. Not the government.

If software is running on your machine that serves someone else's infrastructure, you deserve to know — and you deserve a button that kills it.
