/*
 * Author: Alain Lanthier
 */

#include "../include/terminal.h"
#include "../include/ysClient.h"
#include <stdarg.h>

using Term::Terminal;
using Term::fg;
using Term::bg;
using Term::style;
using Term::Key;


struct ClientTerm
{
    ysSocket::ysClient* netw_client = nullptr;

    int nrows;
    int ncols;

    int nrow_history;
    int nrow_edit;
    int nrow_status;

    char editmsg[800] = { 0 };
    std::string status_msg;

    void add_to_history(bool is_receive, uint8_t msg_type, std::string& msg)
    {
        netw_client->add_to_history(is_receive, msg_type, msg );
    }

    void draw_edit_msg(std::string& ab)
    {
        ab.append(Term::erase_to_eol());
        int msglen = strlen(editmsg);
        ab.append(std::string(editmsg, msglen));
        ab.append("\r\n");

        {
            ab.append(Term::erase_to_eol());
            ab.append("\r\n");
        }
    }

    void set_edit_msg(const char* fmt, ...)
    {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(editmsg, sizeof(editmsg), fmt, ap);
        va_end(ap);
    }

    void draw_history(std::string& ab)
    {
        int cnt = 0;
        auto vh = netw_client->get_vhistory(); // get a copy since multi thread ressource
        int idx = ((int)vh.size()) - nrow_history;
        if (idx < 0) idx = 0;
        for (int i = idx; i < (int)vh.size(); i++)
        {
            {
                ab.append(std::to_string(i+1));
                ab.append(" ");
                ab.append(vh[i].is_receive?"recv ":"send ");
                ab.append(" : ");
                ab.append(vh[i].msg);
                ab.append(Term::erase_to_eol());
                ab.append("\r\n");
                cnt++;
            }
        }


        for (int i = cnt; i < nrow_history + 2; i++)
        {
            ab.append(" ");
            ab.append(Term::erase_to_eol());
            ab.append("\r\n");
        }
    }

    void draw_status_msg(std::string& ab)
    {
        ab.append(Term::erase_to_eol());
        ab.append("Status: ");

//        size_t msglen = status_msg.size();
//        if (msglen > ncols - 10)
//        {
//        }
        ab.append(status_msg);
        ab.append("\r\n");
    }

    void refresh_screen(const Terminal& term)
    {
        int rows, cols;
        term.get_term_size(rows, cols);
        Term::Window win(1, 1, cols, rows);
        win.clear();

        std::string ab;
        ab.reserve(16 * 1024);

        ab.append(Term::cursor_off());
        ab.append(Term::move_cursor(1, 1));

        draw_history(ab);
        draw_edit_msg(ab);
        draw_status_msg(ab);

        term.write(ab);
    }

    ClientTerm(int r, int c) : nrows(r), ncols(c)
    {
        //int nrow_edit = 2;
        //int nrow_status = 1;
        nrow_history = nrows - 6;
    }

    char* prompt_msg(const Terminal& term, const char* prompt, void (*callback)(char*, int))
    {
        size_t bufsize = 128;
        char* buf = (char*)malloc(bufsize);

        size_t buflen = 0;
        buf[0] = '\0';

        while (1)
        {
            {
                set_edit_msg(prompt, buf);
                refresh_screen(term);

                int c = term.read_key();
                if (c == Key::DEL || c == CTRL_KEY('h') || c == Key::BACKSPACE)
                {
                    if (buflen != 0) buf[--buflen] = '\0';
                }
                else if (c == Key::ESC)
                {
                    set_edit_msg("");
                    //if (callback) callback(buf, c);
                    free(buf);
                    return NULL;
                }
                else if (c == Key::ENTER)
                {
                    if (buflen != 0)
                    {
                        set_edit_msg("");
                        //if (callback) callback(buf, c);
                        return buf;
                    }
                }
                else if (!myiscntrl(c) && c >= 32 && c < 127 )// printable char
                {
                    if (buflen == bufsize - 1)
                    {
                        bufsize *= 2;
                        buf = (char*)realloc(buf, bufsize);
                    }
                    buf[buflen++] = c;
                    buf[buflen] = '\0';
                }
            }

            //if (callback) callback(buf, c);
        }
    }
};

int mainMenu(ysSocket::ysClient* netwclient)
{
    try {
        Terminal term(true, false);
        term.save_screen();
        int rows, cols;
        term.get_term_size(rows, cols);

        ClientTerm ct(rows, cols);
        ct.netw_client = netwclient;

        bool on = true;
        Term::Window scr(1, 1, cols, rows);

        // LOOP
        while (on)
        {
            char* e = ct.prompt_msg(term, "Entry: %s (Use ESC/Enter)", NULL);
            if (e != NULL)
            {
                std::string message = std::string(e, strlen(e));

                {
                    std::string key;
                    if (!ct.netw_client->key_valid)
                        key = ct.netw_client->get_DEFAULT_KEY();
                    else if (!ct.netw_client->rnd_valid)
                        key = ct.netw_client->get_initial_key();
                    else
                        key = ct.netw_client->get_random_key();

                    MSG m;
                    m.make_msg(MSG_TEXT, message, key);
                    ct.netw_client->send_message_uffer(ct.netw_client->get_socket(), m, key);

                    ct.netw_client->add_to_history(false, MSG_TEXT, message);
                }

                free(e);
            }
        }
    } catch(const std::runtime_error& re) {
        std::cerr << "Runtime error: " << re.what() << std::endl;
        return 2;
    } catch(...) {
        std::cerr << "Unknown error." << std::endl;
        return 1;
    }
    return 0;
}
