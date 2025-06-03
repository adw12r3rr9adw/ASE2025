#include <stdio.h>
#include <string>
#include <algorithm>
using namespace std;

bool is_palindrome(string str) {
    // Test if given string is a palindrome
    string s(str.rbegin(), str.rend());
    return s == str;
}

string make_palindrome(string str) {
    /*
    Find the shortest palindrome that begins with a supplied string.
    Algorithm idea is simple:
    - Find the longest postfix of supplied string that is a palindrome.
    - Append to the end of the string reverse of a string prefix that comes before the palindromic suffix.
    >>> make_palindrome("")
    ""
    >>> make_palindrome("cat")
    "catac"
    >>> make_palindrome("cata")
    "catac"
    */
    if (str.empty())
        return str;
    int n = str.length();
    int longest_palindrome_suffix = 0;
    for (int i = n; i >= 0; i--) {
        if (is_palindrome(str.substr(0, i))) {
            longest_palindrome_suffix = i;
            break;
        }
    }
    string prefix = str.substr(longest_palindrome_suffix);
    reverse(prefix.begin(), prefix.end());
    return str + prefix;
}

#undef NDEBUG
#include <assert.h>
int main() {
    assert(make_palindrome("") == "");
    assert(make_palindrome("cat") == "catac");
    assert(make_palindrome("cata") == "catac");
    printf("All tests passed!\n");
    return 0;
}