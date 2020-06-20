// **************************************************************************
//  File       [main.cpp]
//  Author     [Yu-Ling Hsu]
//  Modify     [2020/06/10 Yu-Ling Hsu]
// *************************************************************************

#include <iostream>
#include <fstream>
#include <vector>
#include <bits/stdc++.h>
using namespace std;

void helpmessage()
{
    cout << "usage: ./T-Rex <input_file>" << endl;
}

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        helpmessage();
    }

    //////////// read the input file /////////////
    int count = 0;
    string buffer;
    fstream fin(argv[1]);
    while (fin >> buffer)
    {
        ++count;
        if(count < 49){
            //cout<< buffer << endl;
            continue;
        }

        switch (buffer[0])
        {
        case '!':
            switch (buffer[1])
            {
            case '!':
                cout << "V";
                break;
            case '@':
                cout << "5";
                break;
            case '#':
                cout << "I";
                break;
            case '$':
                cout << "K";
                break;
            case '%':
                cout << "E";
                break;
            case '&':
                cout << "U";
                break;
            default:
                cout << buffer;
                break;
            }
            break;
        case '@':
            switch (buffer[1])
            {
            case '!':
                cout << "F";
                break;
            case '@':
                cout << "0";
                break;
            case '#':
                cout << "W";
                break;
            case '$':
                cout << "G";
                break;
            case '%':
                cout << "3";
                break;
            case '&':
                cout << "Z";
                break;
            default:
                cout << buffer;
                break;
            }
            break;
        case '#':
            switch (buffer[1])
            {
            case '!':
                cout << "Y";
                break;
            case '@':
                cout << "M";
                break;
            case '#':
                cout << "H";
                break;
            case '$':
                cout << "B";
                break;
            case '%':
                cout << "C";
                break;
            case '&':
                cout << "8";
                break;
            default:
                cout << buffer;
                break;
            }
            break;
        case '$':
            switch (buffer[1])
            {
            case '!':
                cout << "J";
                break;
            case '@':
                cout << "2";
                break;
            case '#':
                cout << "S";
                break;
            case '$':
                cout << "X";
                break;
            case '%':
                cout << "7";
                break;
            case '&':
                cout << "R";
                break;
            default:
                cout << buffer;
                break;
            }
            break;
        case '%':
            switch (buffer[1])
            {
            case '!':
                cout << "6";
                break;
            case '@':
                cout << "9";
                break;
            case '#':
                cout << "4";
                break;
            case '$':
                cout << "T";
                break;
            case '%':
                cout << "P";
                break;
            case '&':
                cout << "D";
                break;
            default:
                cout << buffer;
                break;
            }
            break;
        case '&':
            switch (buffer[1])
            {
            case '!':
                cout << "1";
                break;
            case '@':
                cout << "L";
                break;
            case '#':
                cout << "Q";
                break;
            case '$':
                cout << "A";
                break;
            case '%':
                cout << "N";
                break;
            case '&':
                cout << "O";
                break;
            default:
                cout << buffer;
                break;
            }
            break;
        default:
            cout << buffer;
            break;
        }
    }
    cout << endl;
    return 0;
}
