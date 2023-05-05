#include "trie.h"

int getidx(char ch) {
	// trie구조를 만들 때 사용
	// domain addr는 .,-,알파벳, 0-9 만 가능
	// Host addr host addr는 case-sensitive 하지 않으므로, 대소문자를 같은 idx로 처리
	// 0~9 : '0' ~ '9'
	// 10 ~ 35 : 'a' ~ 'z'
	// 36 : '.'
	// 37 : '-'
	if ( '0' <= ch && ch <= '9')
		return ch - '0';
	else if ('A' <= ch && ch <= 'Z')
		return ch - 'A';
	else if ('a' <= ch && ch <= 'z')
		return ch - 'a';
	else if (ch == '.')
		return 36;
	else if (ch == '-')
		return 37;
	else  // Unexpected input
		return -1;
}

TrieNode::TrieNode() {
    isEnd = false;
    memset(children, 0, sizeof(children)); 
}

TrieNode::~TrieNode() {
    for (int i = 0; i < 38; i++) {
        delete children[i];
    }
}

Trie::Trie() {
    root = new TrieNode();
}

Trie::~Trie() {
    delete root;
}

void Trie::insert(const string word) {
    TrieNode* current = root;
    for (char c : word) {
        int idx = getidx(c);
        if (idx == -1) {
            return ;
        }
        
        if (current->children[idx] == 0) {
            current->children[idx] = new TrieNode();
        }
        current = current->children[idx];
    }
    current->isEnd = true;
}

bool Trie::search(const string word) {
    TrieNode* current = root;
    for (char c : word) {
        int idx= getidx (c);
        if (idx == -1 ){
            return false;
        }
        if (current->children[idx] == 0) {
            return false;
        }
        current = current->children[idx];
    }
    return current->isEnd;
}