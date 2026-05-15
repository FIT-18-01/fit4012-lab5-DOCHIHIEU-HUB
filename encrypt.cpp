int main() {

    cout << "=============================" << endl;
    cout << " 128-bit AES Encryption Tool " << endl;
    cout << "=============================" << endl;

    string inputStr;
    cout << "Enter the message to encrypt: ";
    getline(cin, inputStr);

    // PKCS#7 padding
    int originalLen = inputStr.size();
    int padLen = 16 - (originalLen % 16);

    if (padLen == 0) {
        padLen = 16;
    }

    int paddedMessageLen = originalLen + padLen;

    // Create buffers
    std::vector<unsigned char> paddedMessage(paddedMessageLen);
    std::vector<unsigned char> encryptedMessage(paddedMessageLen);

    // Copy original message
    for (int i = 0; i < originalLen; i++) {
        paddedMessage[i] = static_cast<unsigned char>(inputStr[i]);
    }

    // Add padding
    for (int i = originalLen; i < paddedMessageLen; i++) {
        paddedMessage[i] = static_cast<unsigned char>(padLen);
    }

    // Read key from file
    string str;
    ifstream infile("keyfile", ios::in | ios::binary);

    if (infile.is_open()) {
        getline(infile, str);
        infile.close();
    }
    else {
        cout << "Unable to open keyfile" << endl;
        return 1;
    }

    // Convert hex string to key bytes
    istringstream hex_chars_stream(str);

    unsigned char key[16];
    unsigned int c;
    int i = 0;

    while (hex_chars_stream >> hex >> c && i < 16) {
        key[i] = static_cast<unsigned char>(c);
        i++;
    }

    // Expand key
    unsigned char expandedKey[176];
    KeyExpansion(key, expandedKey);

    // Encrypt each 16-byte block
    for (int i = 0; i < paddedMessageLen; i += 16) {
        AESEncrypt(&paddedMessage[i], expandedKey, &encryptedMessage[i]);
    }

    // Print encrypted message
    cout << "Encrypted message in hex:" << endl;

    for (int i = 0; i < paddedMessageLen; i++) {
        cout << hex << (int)encryptedMessage[i] << " ";
    }

    cout << endl;

    // Write encrypted output to file
    ofstream outfile("message.aes", ios::out | ios::binary);

    if (outfile.is_open()) {
        outfile.write(
            reinterpret_cast<const char*>(encryptedMessage.data()),
            paddedMessageLen
        );

        outfile.close();

        cout << "Wrote encrypted message to file message.aes" << endl;
    }
    else {
        cout << "Unable to create output file" << endl;
    }

    return 0;
}