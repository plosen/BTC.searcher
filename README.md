# 🚀 Crypto Wallet Scanner

Welcome to **Crypto Wallet Scanner** — a powerful, multi-threaded Python tool for scanning cryptocurrency wallets (Bitcoin and Ethereum) with non-zero balances! 🪙✨

## 🎯 Features

* 🔥 **Multi-threaded scanning:** Supercharges the scanning process with multiple threads!
* 🪙 **Bitcoin and Ethereum support:** Checks balances for both BTC and ETH wallets.
* ⛓️ **Block range scanning:** Generate keys by scanning specific Bitcoin block ranges.
* 📄 **Address file processing:** Reads Bitcoin addresses from a file and scans them (supports resuming!).
* 🧩 **Custom hash input:** Generate BTC and ETH keys from your own hash value.
* 🔄 **Mempool scanning (Bitcoin):** Optionally scan Bitcoin mempool for unconfirmed transactions.
* 🛡️ **Proxy support:** Choose to use a proxy server or connect directly.
* 🕒 **Adjustable delay:** Fine-tune the delay between API requests to avoid rate limits.
* 📝 **Detailed output:** Shows addresses, private keys, and balances found.
* 💾 **Result saving:** Stores scanned results and found keys separately in the `results/` folder.
* 🧑‍💻 **Interactive menu:** User-friendly command-line interface for easy configuration.
* 🛟 **Progress saving:** Resume file scanning from where you left off — no data loss!
* 🎯 **Start from specific address:** Option to start scanning from a selected address inside a file.

---

## ⚙️ Installation

1. **Clone the repository** (if you have one):
    ```bash
    git clone https://github.com/plosen/BTC.searcher
    cd https://github.com/plosen/BTC.searcher
    ```

2. **Install the required Python libraries:**
    ```bash
    pip install requests bitcoinutils eth-account colorama
    ```

---

## 🏁 Usage

1. **Run the script:**
    ```bash
    python btc_searcher.py
    ```
    (Replace `btc_searcher.py` with the actual file name.)

2. **Follow the interactive menu:**
    * Configure settings like **proxy usage**, **delay**, and **mempool scan**.
    * Choose a scanning mode:
        * 🔹 **1 - Block scanning:** Enter a block range (e.g., `100-200` or `100,150,200`).
        * 🔹 **2 - Process file with BTC addresses:** Provide a file path with Bitcoin addresses.
        * 🔹 **3 - Manual hash input:** Enter your own hash for custom key generation.
    * Set the number of **threads**, **delay** between API requests, and other parameters.
    * Confirm configuration and start the magic! ✨

3. **View your results:**
    * All scanned addresses: `results/all_results.txt`
    * Found wallets with balances (with private keys!): `results/FOUND_KEYS.txt`

---

## 📢 Important Notes

* 🔑 **API Keys:**  
  The script uses an **Etherscan API key**. It's hardcoded but you may replace it with your own if needed — especially for heavy scanning sessions.
  
* 🌐 **Proxy:**  
  A proxy is included by default. You can disable or edit it easily via the interactive menu.

* ⚡ **Rate Limiting:**  
  Adjust the delay wisely to comply with API rate limits. Fast scanning = possible bans if you're not careful!

* ⚖️ **Ethical Disclaimer:**  
  This tool is for **educational purposes only**. Attempting unauthorized wallet access is illegal and unethical. 🚫

* 🎲 **Probability Warning:**  
  The probability of randomly finding a wallet with balance is **extremely low** — practically zero. This project is a fun exploration of crypto math, not a "money machine." 🧠

---

## 🤝 Contributing

Got ideas? Found bugs? Open a pull request or create an issue! Contributions are welcome! 🎉

---

## 🪪 License

[Choose a license and add it here, e.g., MIT License]

---

# 📂 Other Files for GitHub Setup

**1. `.gitignore`**  
Create a `.gitignore` file to keep your repo clean:

```gitignore
__pycache__/
*.pyc
*.log
results/
scan_progress.txt
.idea/
*.iml
