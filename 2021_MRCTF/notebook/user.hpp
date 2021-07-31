#pragma once

#include <utility>
#include <vector>
#include <string>
#include <cstring>
#include <unistd.h>
#include <cstdio>
#include <iostream>
#include <random>
#include <memory>

using namespace std;

class User {
private:
#define MAX_NOTE 8
	pair <string, string> passwd;
	shared_ptr<string> note[MAX_NOTE];
    bool is_login = false;
	int max_note;
	int pid;
	void (User::*hello)();
public:
	User(string username = "admin", string password = "123456") {
        int tmp;
        char buf[65] = {};
		random_device rd;
		mt19937 mt(rd());
		passwd.first = username;
		if (passwd.first == "admin") {
            for (int i = 0; i < 64; ++i) {
                buf[i] = mt() % 79 + 48;
            }
            passwd.second = buf;
			pid = 0;
		} else {
            passwd.second = password;
			pid = 1000;
        }
		max_note = 1;
		hello = &User::helloUser;
	}
	~User() {
	}
	string getName() {
		if (is_login) {
			return passwd.first;
		} else {
			return "guest";
		}
	}
	void loginUser() {
		while (!is_login) {
			int chose;
			cout << "###############" << endl;
			cout << "# 1 Login in  #" << endl;
			cout << "# 2 Exit      #" << endl;
			cout << "###############" << endl;
			cin >> chose;
			switch (chose) {
				case 1:
					char buf[0x100];
					int i;
					cin >> buf;
					for (i = 0; i < passwd.second.size(); i += 1) {
						if (buf[i] != passwd.second[i]) {
							cout << "Wrong : " << buf << endl;
							break;
						}
					}
					if (i == passwd.second.size()) {
						is_login = true;
						if (pid == 0 && passwd.first == "admin") {
							max_note = MAX_NOTE;
							hello = &User::helloAdmin;
						}
						(this->*hello)();
					}
				break;
				case 2:
					exit(0);
					break;
			}
		}
	}
	void addNote() {
		cout << "Note ID" << endl;
		cout << ">";
		unsigned int idx;
        cin >> idx;
		if (idx < max_note) {
			note[idx] = make_shared<string>();
		} else {
			cout << "Out of range, you can only use " << max_note << " note. " << endl;
		}
	}
	void removeNote() {
		cout << "Note ID" << endl;
		cout << ">";
		unsigned int idx;
        cin >> idx;
	}
	void editNote() {
		cout << "Note ID" << endl;
		cout << ">";
		unsigned int idx;
        cin >> idx;
		if (idx < max_note && note[idx]) {
			cout << "Note" << endl;
			cout << ">";
			cin >> *note[idx];
		} else {
			cout << "Out of range, you can only use " << max_note << " note. " << endl;
		}
	}
	void showNote() {
		cout << "Note ID" << endl;
		cout << ">";
		unsigned int idx;
		cin >> idx;
		if (idx < max_note && note[idx]) {
			cout << *note[idx] << endl;
		}
	}
	void helloAdmin() {
		free(*(char**)&*note[0]);
		cout << "Login Success! " << getName() << endl;
	}
	void helloUser() {
		cout << "Login Success! " << getName() << endl;
	}
}; //class User