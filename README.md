# 🔍 BreachScanner

A Go tool that checks if your email has been exposed in known data breaches.

## What It Does

- Takes an email address
- Checks against the HackMyIP breach API
- Reports: breach count, affected services, risk score, password exposure
- Generates personalized security recommendations

## Installation

```bash
git clone https://github.com/Aaronmike481/BreachScanner.git
cd BreachScanner
go mod tidy