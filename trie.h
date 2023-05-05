#include<string>
#include<cstring> //memset
using namespace std;


int getidx(char ch);

class TrieNode {
public:
    bool isEnd;
    TrieNode* children[38];

    TrieNode();

    ~TrieNode();
};

class Trie {
public:
    Trie();

    ~Trie();
    void insert(const string word);

    bool search(const string word);

private:
    TrieNode* root;
};
