string getpart(string str, int start, int end)
{
    string output;
    for(int i = start; i < end; i++)
        output += str[i];
    return output;
}

string encrypt(const string text, const string key, const int len)
{
    string output;
    int i, le = text.length();

    for(i = 1; i <= le; i++)
        output += sha256(text.substr(0, i) + key).substr(0, len);
    return output;
}

string decrypt(const string digest, const string key, const int len)
{
    string output, current_block;
    int i, ch, blocks = digest.length() / len;

    for(i = 0; i < blocks; i++)
    {
        current_block = getpart(digest, i*len, (i+1)*len);
        for(ch = 0; ch < 128; ch++)
        {
            if(current_block == sha256(output + (char)ch + key).substr(0, len))
            {
                output += (char)ch;
                break;
            }
            if(ch == 127)
                return "Wrong key!";
        }
    }
    return output;
}