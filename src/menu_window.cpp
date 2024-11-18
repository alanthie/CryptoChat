/*
 * Author: Alain Lanthier
 */

#include "../include/terminal.h"
#include "../include/ysClient.h"
#include "../include/data.hpp"
#include "../include/string_util.hpp"
#include "../include/file_util.hpp"
#include "../include/main_global.hpp"
#include <stdarg.h>

using Term::Terminal;
using Term::fg;
using Term::bg;
using Term::style;
using Term::Key;


struct ClientTerm
{
    const int MAX_EXTRA_LINE_TO_DISPLAY = 40;
    ysSocket::ysClient* netw_client = nullptr;

    // Updated by term.get_term_size(rows, cols);
    int nrows;
    int ncols;

    // allow PageUP, PageDOWN ArrowUP, ArrowDOWN
    int first_row = 0;              // first row to display for vallrows
    int first_row_fileview = 0;     // first row to display for vfilerows
    int first_row_log_view = 0;     // first row to display for vlogrows
    std::vector<std::string> vallrows;      // chat view
    std::vector<std::string> vfilerows;     // file view
    std::vector<std::string> vlogrows;      // log view

    std::vector<char> vallrows_is_file;
    std::vector<char> vallrows_is_send;
    std::vector<std::string> vallrows_filename_key;

    bool is_file_view_dirty = true;
    std::string file_view_filename_key;

    char editmsg[256] = { 0 };
    std::string status_msg;

    int _mode = 0; // 0 = chat view, 1 = file view, 2 = log view

    // chat view cursor position in screen
    int cursor_x=0;
    int cursor_y=0;

    ClientTerm(int r, int c) : nrows(r), ncols(c)
    {
    }

    bool is_file_command(const std::string& m)
    {
        if (m.size() < 5) return false;
        if ((m[0]=='<') && (m[1]=='<') && (m[m.size()-1]=='>') && (m[m.size()-2]=='>'))
            return true;
        return false;
    }
    bool is_binfile_command(const std::string& m)
    {
        if (m.size() < 5) return false;
        if ((m[0] == '[') && (m[1] == '[') && (m[m.size() - 1] == ']') && (m[m.size() - 2] == ']'))
            return true;
        return false;
    }
    std::string file_from_command(const std::string& m)
    {
        return m.substr(2, m.size()-4);
    }
    std::string read_file(const std::string& fname)
    {
        cryptoAL::cryptodata file;
        if (file.read_from_file(fname))
        {
            return std::string(file.buffer.getdata(), file.buffer.size());
        }
        return {};
    }

    void add_to_history(bool is_receive, uint8_t msg_type, std::string& msg, std::string filename, std::string filename_key, bool is_for_display)
    {
        netw_client->add_to_history(is_receive, msg_type, msg, filename, filename_key, is_for_display);
    }

    void draw_edit_msg(std::string& ab)
    {
        ab.append(Term::erase_to_eol());
        int msglen = strlen(editmsg);
        ab.append(std::string(editmsg, msglen)); // ncols ...
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

    std::string get_printable_string(const std::string& line)
    {
        std::string s(line.size(), ' ');
        char c;
        for (size_t i=0;i<line.size();i++)
        {
            c = line[i];
            if ((c >= 32) && (c < 127)) s[i] = c;
            else s[i] = '_';
        }
        return s;
    }

    void process_move_keys(int c, const Terminal& term)
    {
        if (c == Key::PAGE_UP || c == Key::PAGE_DOWN || c == Key::ARROW_UP || c == Key::ARROW_DOWN)
        {
            if (_mode == 0)
            {
                if (vallrows.size() > (nrows - 4))
                {
                    if (c == Key::PAGE_UP)
                    {
                        first_row = first_row - (nrows - 4);
                        if (first_row < 0) first_row = 0;
                        refresh_screen(term, false);
                    }
                    else if (c == Key::PAGE_DOWN)
                    {
                        first_row = first_row + (nrows - 4);
                        if (first_row > vallrows.size() - (nrows - 4))
                            first_row = vallrows.size() - (nrows - 4);
                        refresh_screen(term, false);
                    }
                }

                if (c == Key::ARROW_UP)
                {
                    if (cursor_y == 0)
                    {
                        first_row = first_row - 1;
                        if (first_row < 0) first_row = 0;
                    }
                    else
                    {
                        cursor_y--;
                    }
                    refresh_screen(term, false);
                }
                else if (c == Key::ARROW_DOWN)
                {
                    if (cursor_y == (nrows - 4) - 1)
                    {
                        if (vallrows.size() > (nrows - 4))
                        {
                            first_row = first_row + 1;
                            if (first_row > vallrows.size() - (nrows - 4))
                                first_row = vallrows.size() - (nrows - 4);
                        }
                    }
                    else
                    {
                        cursor_y++;
                    }
                    refresh_screen(term, false);
                }
            }
            else if (_mode == 2)
            {
                if (vlogrows.size() > (nrows - 4))
                {
                    if (c == Key::PAGE_UP)
                    {
                        first_row_log_view = first_row_log_view - (nrows - 4);
                        if (first_row_log_view < 0) first_row_log_view = 0;
                        refresh_screen(term, false);
                    }
                    else if (c == Key::PAGE_DOWN)
                    {
                        first_row_log_view = first_row_log_view + (nrows - 4);
                        if (first_row_log_view > vlogrows.size() - (nrows - 4))
                            first_row_log_view = vlogrows.size() - (nrows - 4);
                        refresh_screen(term, false);
                    }
                    else if (c == Key::ARROW_UP)
                    {
                        first_row_log_view = first_row_log_view - 1;
                        if (first_row_log_view < 0) first_row_log_view = 0;
                        refresh_screen(term, false);
                    }
                    else if (c == Key::ARROW_DOWN)
                    {
                        first_row_log_view = first_row_log_view + 1;
                        if (first_row_log_view > vlogrows.size() - (nrows - 4))
                            first_row_log_view = vlogrows.size() - (nrows - 4);
                        refresh_screen(term, false);
                    }
                }
            }
            else if (_mode == 1)
            {
                if (vfilerows.size() > (nrows - 4))
                {
                    if (c == Key::PAGE_UP)
                    {
                        first_row_fileview = first_row_fileview - (nrows - 4);
                        if (first_row_fileview < 0) first_row_fileview = 0;
                        refresh_screen(term, false);
                    }
                    else if (c == Key::PAGE_DOWN)
                    {
                        first_row_fileview = first_row_fileview + (nrows - 4);
                        if (first_row_fileview > vfilerows.size() - (nrows - 4))
                            first_row_fileview = vfilerows.size() - (nrows - 4);
                        refresh_screen(term, false);
                    }
                    else if (c == Key::ARROW_UP)
                    {
                        first_row_fileview = first_row_fileview - 1;
                        if (first_row_fileview < 0) first_row_fileview = 0;
                        refresh_screen(term, false);
                    }
                    else if (c == Key::ARROW_DOWN)
                    {
                        first_row_fileview = first_row_fileview + 1;
                        if (first_row_fileview > vfilerows.size() - (nrows - 4))
                            first_row_fileview = vfilerows.size() - (nrows - 4);
                        refresh_screen(term, false);
                    }
                }
            }
        }
    }

    void draw_history(std::string& ab, bool is_dirty = true)
    {
        // File view
        if (_mode==1)
        {
            if (is_dirty)
            {
                vfilerows.clear();
                file_view_filename_key = {};

                bool is_msgfile = false;
                int row_cursor = first_row + cursor_y;
                if (row_cursor < vallrows_is_file.size() && row_cursor >= 0)
                {
                    if (vallrows_is_file[row_cursor] == 1)
                    {
                        is_msgfile = true;
                    }
                }

                if (is_msgfile)
                {
                    std::string filename_key = vallrows_filename_key[row_cursor];
                    size_t byte_processed;
                    size_t total_size = 1;
                    bool is_done;

                    file_view_filename_key = filename_key;

                    if (filename_key.size() > 0)
                    {
                        bool r;
                        if (vallrows_is_send[row_cursor])
                            r = netw_client->get_info_file_to_send(filename_key, byte_processed, total_size, is_done);
                        else
                            r = netw_client->get_info_file_to_recv(filename_key, byte_processed, total_size, is_done);

                        if (r)
                        {
                            if (is_done)
                            {
                                std::string s;
                                if (vallrows_is_send[row_cursor])
                                    s = netw_client->get_file_to_send(filename_key);
                                else
                                    s = netw_client->get_file_to_recv(filename_key);

                                if (s.size() > 0)
                                {
                                    vfilerows = NETW_MSG::split(s, "\n");
                                }
                            }
                        }
                    }
                }
            }

            if (vfilerows.size() == 0)
            {
                first_row_fileview = 0;
                ab.append("No file to show (move cursor to a file send or recv)");
                ab.append(Term::erase_to_eol());
                ab.append("\r\n");

                for (int i = 1; i < nrows - 4; i++)
                {
                    ab.append(" ");
                    ab.append(Term::erase_to_eol());
                    ab.append("\r\n");
                }
                return;
            }

            {
                // shows nrows - 4 at most
                // first row is at n_rows - nrows + 4
                int cnt = 0;
                int n_total_rows = vfilerows.size();

                if (is_dirty)
                {
                    first_row_fileview = n_total_rows - (nrows - 4);
                    if (first_row_fileview < 0) first_row_fileview = 0;
                }

                for (int i = first_row_fileview; i < (int)vfilerows.size(); i++)
                {
                    ab.append("[" + std::to_string(i) + "]: ");
                    ab.append(vfilerows[i]);
                    ab.append(Term::erase_to_eol());
                    ab.append("\r\n");
                    cnt++;

                    if (cnt >= nrows - 4)
                        break;
                }

                for (int i = cnt; i < nrows - 4; i++)
                {
                    ab.append(" ");
                    ab.append(Term::erase_to_eol());
                    ab.append("\r\n");
                }
            }
            return;
        }

        // Log view
        else if (_mode==2)
        {
            if (is_dirty)
            {
                std::string log_str = main_global::get_log_string();
                vlogrows = NETW_MSG::split(log_str, "\n");

                if (vlogrows.size() == 0)
                {
                    first_row_log_view = 0;
                    ab.append("Log is empty");
                    ab.append(Term::erase_to_eol());
                    ab.append("\r\n");

                    for (int i = 1; i < nrows - 4; i++)
                    {
                        ab.append(" ");
                        ab.append(Term::erase_to_eol());
                        ab.append("\r\n");
                    }
                    return;
                }
            }

            {
                // shows nrows - 4 at most
                // first row is at n_rows - nrows + 4
                int cnt = 0;
                int n_total_rows = vlogrows.size();

                if (is_dirty)
                {
                    first_row_log_view = n_total_rows - (nrows - 4);
                    if (first_row_log_view < 0) first_row_log_view = 0;
                }

                for (int i = first_row_log_view; i < (int)vlogrows.size(); i++)
                {
                    ab.append("[" + std::to_string(i) + "]: ");
                    ab.append(vlogrows[i]);
                    ab.append(Term::erase_to_eol());
                    ab.append("\r\n");
                    cnt++;

                    if (cnt >= nrows - 4)
                        break;
                }

                for (int i = cnt; i < nrows - 4; i++)
                {
                    ab.append(" ");
                    ab.append(Term::erase_to_eol());
                    ab.append("\r\n");
                }
            }

            return;
        }

        else if (_mode == 0)
        {
            if (is_dirty)
            {
                size_t histo_cnt;
                auto vh = netw_client->get_vhistory(histo_cnt); // get a copy since multi thread ressource

                // fill vh[i].vmsg_extra
                for (int i = 0; i < (int)vh.size(); i++)
                {
                    if (vh[i].msg_type == NETW_MSG::MSG_FILE)
                    {
                        if (vh[i].is_for_display && vh[i].vmsg_extra.size() == 0)
                        {
                            size_t byte_processed;
                            size_t total_size = 1;
                            bool is_done;

                            if (vh[i].is_receive == false)
                            {
                                bool r = netw_client->get_info_file_to_send(vh[i].filename_key, byte_processed, total_size, is_done);
                                if (r)
                                {
                                    if (is_done && vh[i].vmsg_extra.size() == 0)
                                    {
                                        std::string s = netw_client->get_file_to_send(vh[i].filename_key);
                                        if (s.size() > 0)
                                        {
                                            vh[i].vmsg_extra = NETW_MSG::split(s, "\n");
                                        }
                                    }
                                }
                            }
                            else
                            {
                                bool r = netw_client->get_info_file_to_recv(vh[i].filename_key, byte_processed, total_size, is_done);
                                if (r)
                                {
                                    if (is_done && vh[i].vmsg_extra.size() == 0)
                                    {
                                        std::string s = netw_client->get_file_to_recv(vh[i].filename_key);
                                        if (s.size() > 0)
                                        {
                                            vh[i].vmsg_extra = NETW_MSG::split(s, "\n");
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                //int row_cursor = first_row + cursor_y;
                vallrows.clear();
                vallrows_is_file.clear();
                vallrows_is_send.clear();
                vallrows_filename_key.clear();

                char is_file_line;
                bool is_file_send;
                std::string filename_key;

                for (int i = 0; i < (int)vh.size(); i++)
                {
                    std::string work;
                    {
                        std::vector<std::string> vlines = NETW_MSG::split(vh[i].msg, "\r\n");

                        // only consider first line...
                        for (size_t j = 0; j < 1; j++)
                        {
                            work.append(std::to_string(histo_cnt - vh.size() + i + 1));
                            work.append(" ");
                            work.append(vh[i].is_receive ? "recv " : "send ");
                            work.append(": ");

                            std::string sl;
                            if (vh[i].msg_type != NETW_MSG::MSG_FILE)
                            {
                                is_file_line = false;
                                sl = get_printable_string(vlines[j]);
                                filename_key = {};
                                is_file_send = !vh[i].is_receive;
                            }
                            else
                            {
                                sl = vh[i].filename;
                                is_file_line = true;
                                is_file_send = !vh[i].is_receive;
                                filename_key = vh[i].filename_key;
                            }

                            if (vh[i].msg_type == NETW_MSG::MSG_FILE)
                            {
                                size_t byte_processed;
                                size_t total_size = 1;
                                bool is_done;
                                float percent = 0;
                                float fbyte_processed;
                                float ftotal_size;

                                if (vh[i].is_receive == false)
                                {
                                    bool r = netw_client->get_info_file_to_send(vh[i].filename_key, byte_processed, total_size, is_done);
                                    if (r)
                                    {
                                        fbyte_processed = byte_processed;
                                        ftotal_size = total_size;

                                        if (total_size > 0)
                                            if (byte_processed <= total_size)
                                                percent = fbyte_processed / ftotal_size;
                                    }
                                }
                                else
                                {
                                    bool r = netw_client->get_info_file_to_recv(vh[i].filename_key, byte_processed, total_size, is_done);
                                    if (r)
                                    {
                                        fbyte_processed = byte_processed;
                                        ftotal_size = total_size;

                                        if (total_size > 0)
                                            if (byte_processed <= total_size)
                                                percent = fbyte_processed / ftotal_size;
                                    }
                                }

                                int ipercent = (int)(100 * percent);
                                std::string ss = "<<" + sl + ">>" + "[" + std::to_string(ipercent) + "%] size=" + std::to_string(total_size) + "";
                                ss += " Lines=" + std::to_string(vh[i].vmsg_extra.size());
                                work.append(ss); // ncols ...
                            }
                            else
                                work.append(sl); // ncols ...
                        }
                        vallrows.push_back(work);
                        vallrows_is_file.push_back(is_file_line);
                        vallrows_filename_key.push_back(filename_key);
                        vallrows_is_send.push_back(is_file_send);

                        for (size_t j = 0; j < vh[i].vmsg_extra.size(); j++)
                        {
                            work.clear();
                            is_file_line = true;
                            is_file_send = !vh[i].is_receive;
                            filename_key = vh[i].filename_key;

                            if (j < MAX_EXTRA_LINE_TO_DISPLAY - 1)
                            {
                                {
                                    work.append(std::to_string(histo_cnt - vh.size() + i + 1));
                                    work.append(" ");
                                    work.append(vh[i].is_receive ? "< " : "> ");
                                    work.append(": ");
                                    std::string sl = get_printable_string(vh[i].vmsg_extra[j]);
                                    work.append(sl); // ncols ...
                                    vallrows.push_back(work);
                                    vallrows_is_file.push_back(is_file_line);
                                    vallrows_is_send.push_back(is_file_send);
                                    vallrows_filename_key.push_back(filename_key);
                                }
                            }
                            else if (j == MAX_EXTRA_LINE_TO_DISPLAY - 1)
                            {
                                {
                                    work.append(std::to_string(histo_cnt - vh.size() + i + 1));
                                    work.append(" ");
                                    work.append(vh[i].is_receive ? "< " : "> ");
                                    work.append(": ");
                                    std::string sl = "..................";
                                    work.append(sl); // ncols ...
                                    vallrows.push_back(work);
                                    vallrows_is_file.push_back(is_file_line);
                                    vallrows_is_send.push_back(is_file_send);
                                    vallrows_filename_key.push_back(filename_key);
                                }
                            }
                        }
                    }
                }
            }
        }

        // shows nrows - 4 at most
        // first row is at n_rows - nrows + 4
        int cnt = 0;
        int n_total_rows = vallrows.size();

        if (is_dirty)
        {
            first_row = n_total_rows - (nrows - 4);
            if (first_row < 0) first_row = 0;
        }

        // check is_file_view_dirty
        {
            int row_cursor = first_row + cursor_y;
            if (row_cursor >= 0 && row_cursor < vallrows_filename_key.size())
            {
                if (vallrows_is_file[row_cursor] == false)
                {
                    is_file_view_dirty = true;
                }
                else if (vallrows_filename_key[row_cursor] != file_view_filename_key)
                {
                    is_file_view_dirty = true;
                }
            }
        }

        for (int i = first_row; i < (int)vallrows.size(); i++)
        {
            ab.append(vallrows[i]);
            ab.append(Term::erase_to_eol());
            ab.append("\r\n");
            cnt++;

            if (cnt >= nrows - 4)
                break;
        }

        for (int i = cnt; i < nrows - 4; i++)
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

        ab.append(status_msg);
        ab.append("\r\n");
    }

    void refresh_screen(const Terminal& term,  bool is_dirty = true)
    {
        int rows, cols;
        term.get_term_size(rows, cols);
        Term::Window win(1, 1, cols, rows);
        win.clear();

        // update
        nrows = rows;;
        ncols = cols;

        std::string ab;
        ab.reserve(16 * 1024);

        ab.append(Term::cursor_off());
        ab.append(Term::move_cursor(1, 1));

        // ...
        status_msg = "[username=" + netw_client->_cfg_cli._username +"]";
        char host[80];
        if (gethostname(host, 80) == 0)
        {
            status_msg += "[hostname=" + std::string(host) + "]";
        }
        status_msg += "[rows=" + std::to_string(nrows) + "]";
        status_msg += "[cols=" + std::to_string(ncols) + "]";


        draw_history(ab, is_dirty);
        draw_edit_msg(ab);
        draw_status_msg(ab);

        if (_mode == 0)
        {
            ab.append(Term::move_cursor(cursor_y + 1, cursor_x + 1));
            ab.append(Term::cursor_on());
        }

        term.write(ab);
    }

    char* prompt_msg(const Terminal& term, const char* prompt, void (*callback)(char*, int))
    {
        size_t bufsize = 128;
        char* buf = (char*)malloc(bufsize);

        size_t buflen = 0;
        buf[0] = '\0';

        while (1)
        {
            if (netw_client->is_got_chat_cli_signal())
            {
                std::stringstream ss; ss << "Exiting prompt_msg loop " << std::endl;
                main_global::log(ss.str(), true);

                set_edit_msg("");
                free(buf);
                return NULL;
            }

            {
                int c;

                set_edit_msg(prompt, buf);

                if      (_mode == 0)    refresh_screen(term, netw_client->get_ui_dirty());
                else if (_mode == 2)    refresh_screen(term, main_global::is_log_dirty());
                else                    refresh_screen(term, is_file_view_dirty);

                if      (_mode == 0)    netw_client->set_ui_dirty(false);
                else if (_mode == 2)    main_global::set_log_dirty(false);
                else                    is_file_view_dirty = false;

				bool key_read = false;
				while (key_read == false)
				{
                    if (netw_client->is_got_chat_cli_signal())
                    {
						std::stringstream ss; ss << "Exiting prompt_msg loop " << std::endl;
						main_global::log(ss.str(), true);

                        set_edit_msg("");
                        free(buf);
                        return NULL;
                    }

					c = term.try_read_key(key_read) ;
					if (key_read == false)
					{
                        bool refresh = false;
                        if (_mode == 0)
                        {
                            if (netw_client->get_ui_dirty())
                            {
                                refresh_screen(term, true);
                                netw_client->set_ui_dirty(false);
                                refresh = true;
                            }
                        }
                        else if (_mode == 2)
                        {
                            if (main_global::is_log_dirty())
                            {
                                refresh_screen(term, true);
                                main_global::set_log_dirty(false);
                                refresh = true;
                            }
                        }

                        if (refresh==false)
						{
							std::this_thread::sleep_for(std::chrono::milliseconds(10));
						}
					}
					else
					{
						break;
                    }
				}
                //c = term.read_key();

                if (c == Key::F1)
                {
                    _mode++;
                    if (_mode > 2) _mode = 0;

                    set_edit_msg("");
                    free(buf);
                    return NULL;
                }
                else if (c == Key::DEL || c == CTRL_KEY('h') || c == Key::BACKSPACE)
                {
                    if (buflen != 0) buf[--buflen] = '\0';
                }
                else if (c == Key::ESC)
                {
                    set_edit_msg("");
                    free(buf);
                    return NULL;
                }
                else if (c == Key::ENTER)
                {
                    if (buflen != 0)
                    {
                        set_edit_msg("");
                        return buf;
                    }
                }
                else if (!myiscntrl(c) && c >= 32 && c < 127)// printable char
                {
                    if (buflen == bufsize - 1)
                    {
                        bufsize *= 2;
                        buf = (char*)realloc(buf, bufsize);
                    }
                    buf[buflen++] = c;
                    buf[buflen] = '\0';
                }
                else
                    process_move_keys(c, term);
            }
        }
    }

    void process_prompt(const Terminal& term, char* e)
    {
        ClientTerm& ct =*this;
        if (e != NULL && _mode==0)
        {
            bool is_txtfile_send_cmd = false;
            bool is_binfile_send_cmd = false;
            std::string message = std::string(e, strlen(e));

            std::string filename;
            std::string filename_key;

            if (ct.is_file_command(message))
            {
                filename = ct.file_from_command(message);
                try
                {
                    if (file_util::fileexists(filename))
                    {
                        //test
                        //filename = "/home/allaptop/dev/CryptoChat/lnx_chatcli/bin/Debug/f.txt";

                        filename_key = filename + std::to_string(ct.netw_client->file_counter);
                        ct.netw_client->file_counter++;
                        bool r = ct.netw_client->add_file_to_send(filename, filename_key);
                        if (r)
                        {
                            is_txtfile_send_cmd = true;
                            message = "[" + filename + "," + filename_key + ",1]";
                        }
                    }
                    else
                    {
                        std::stringstream ss;
                        ss << "WARNING - File do not exist: " << filename << std::endl;
                        main_global::log(ss.str());
                    }
                }
                catch (...)
                {
                    std::stringstream ss;
                    ss << "WARNING - Invalid file: " << filename << std::endl;
                    main_global::log(ss.str());
                }
            }
            else if (ct.is_binfile_command(message))
            {
                filename = ct.file_from_command(message);
                try
                {
                    if (file_util::fileexists(filename))
                    {
                        filename_key = filename + std::to_string(ct.netw_client->file_counter);
                        ct.netw_client->file_counter++;
                        bool r = ct.netw_client->add_file_to_send(filename, filename_key);
                        if (r)
                        {
                            is_binfile_send_cmd = true;
                            message = "[" + filename + "," + filename_key + ",0]";
                        }
                    }
                    else
                    {
                        std::stringstream ss;
                        ss << "WARNING - File do not exist: " << filename << std::endl;
                        main_global::log(ss.str());
                    }
                }
                catch (...)
                {
                    std::stringstream ss;
                    ss << "WARNING - Invalid file: " << filename << std::endl;
                    main_global::log(ss.str());
                }
            }

            if (is_binfile_send_cmd || is_txtfile_send_cmd)
            {
                if (message.size() > 0)
                {
                    std::string key;
                    {
                        std::lock_guard l(ct.netw_client->_key_mutex);

                        if (!ct.netw_client->key_valid)
                            key = ct.netw_client->get_DEFAULT_KEY();
                        else if (!ct.netw_client->rnd_valid)
                            key = ct.netw_client->get_initial_key();
                        else
                            key = ct.netw_client->get_random_key();
                    }

                    NETW_MSG::MSG m;
                    m.make_msg(NETW_MSG::MSG_FILE, message, key);
                    ct.netw_client->send_message_buffer(ct.netw_client->get_socket(), m, key);

                    ct.netw_client->add_to_history(false, NETW_MSG::MSG_FILE, message, filename, filename_key, is_txtfile_send_cmd);
                    ct.netw_client->set_ui_dirty();
                }
            }
            else
            {
                if (message.size() > 0)
                {
                    std::string key;
                    {
                        std::lock_guard l(ct.netw_client->_key_mutex);

                        if (!ct.netw_client->key_valid)
                            key = ct.netw_client->get_DEFAULT_KEY();
                        else if (!ct.netw_client->rnd_valid)
                            key = ct.netw_client->get_initial_key();
                        else
                            key = ct.netw_client->get_random_key();
                    }

                    NETW_MSG::MSG m;
                    m.make_msg(NETW_MSG::MSG_TEXT, message, key);
                    ct.netw_client->send_message_buffer(ct.netw_client->get_socket(), m, key);

                    ct.netw_client->add_to_history(false, NETW_MSG::MSG_TEXT, message);
                    ct.netw_client->set_ui_dirty();
                }
            }

            free(e);
        }
    }
};

int main_client_ui(ysSocket::ysClient* netwclient)
{
    try {
        Terminal term(true, false);
        term.save_screen();
        int rows, cols;
        term.get_term_size(rows, cols);

        ClientTerm _ct(rows, cols);
        ClientTerm* ct = &_ct; //new ClientTerm(rows, cols);
        ct->netw_client = netwclient;

        bool on = true;
        Term::Window scr(1, 1, cols, rows);

        // LOOP
        while (on)
        {
            if (netwclient->is_got_chat_cli_signal())
            {
				std::stringstream ss; ss << "Terminating thread client_UI" << std::endl;
				main_global::log(ss.str(), true);

                //delete ct;
                on = false;
                break;
            }

            char* e = ct->prompt_msg(term, "Entry: %s (Use ESC/Enter/PAGE_UP/PAGE_DOWN/ARROW_UP/ARROW_DOWN/<<txt_filename>>/[[bin_filename]])", NULL);
            ct->process_prompt(term, e);

        }
    } catch(const std::runtime_error& re) {
        std::stringstream ss;
        ss << "Runtime error: " << re.what() << std::endl;
        main_global::log(ss.str(),true);
        return 2;
    } catch(...) {
        std::stringstream ss;
        ss << "Unknown error." << std::endl;
        main_global::log(ss.str(),true);
        return 1;
    }
    return 0;
}
