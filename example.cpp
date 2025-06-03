#include <bits/stdc++.h>
using namespace std;


/**
 * Write a function to find the similar elements from the given two tuple lists.
 * > similarElements(vector<int>{3, 4, 5, 6}, vector<int>{5, 7, 4, 10})
 * {4, 5}
 * > similarElements(vector<int>{1, 2, 3, 4}, vector<int>{5, 4, 3, 7})
 * {3, 4}
 * > similarElements(vector<int>{11, 12, 14, 13}, vector<int>{17, 15, 14, 13})
 * {13, 14}
 */
vector<int> similarElements(vector<int> testTup1, vector<int> testTup2) {
    vector<int> result;
    sort(testTup1.begin(), testTup1.end());
    sort(testTup2.begin(), testTup2.end());
    set_intersection(testTup1.begin(), testTup1.end(), testTup2.begin(), testTup2.end(), back_inserter(result));
    return result;
}

int main() {}