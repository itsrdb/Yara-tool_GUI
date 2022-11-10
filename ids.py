import os
import subprocess
import webbrowser
from tkinter import *
from tkinter import ttk
from tkinter import filedialog
from datetime import datetime
#Create an instance of Tkinter frame
root= Tk()
# root.pack()
#Define the geometry
top_frame = Frame(root)
top_frame.pack(side = TOP)
bot_frame = Frame(root)
bot_frame.pack(side= TOP, padx=200)

root.title('YARA Helper by itsrdb')
root.geometry("800x520")
yara = Label(top_frame, text="Please choose a directory to search", font=('Aerial 18 bold')).pack(pady=18)
no_yara = 0
search_dir_var = "?"
yara_list = []

def line_prepender(filename, line):
    with open(filename, 'r+') as f:
        content = f.read()
        f.seek(0, 0)
        f.write(line + '\n' + content)

def select_file():
    path= filedialog.askdirectory(title="Select a File")
    global search_dir_var
    search_dir_var = path
    print(search_dir_var)
    select_dir.config(text=path)
    # Label(top_frame, text=path, font=13).pack()

def add_log(log):
    now = datetime.now()
    dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
    log = "# " + dt_string + '\n' + log
    line_prepender('logs.txt', log)

def execute_cmd(cmd, yara, tx, tx_loc):
    l = cmd.split(' ')
    print(l)
    proc = subprocess.Popen(l, stdout=subprocess.PIPE)
    output = proc.stdout.read()
    n_out = output.decode()
    # print(n_out)
    global T
    temp_l = yara.split('/')
    yara_name = temp_l[-1]
    print(yara, yara_name)
    if len(n_out) > 0:
        ans = "Found result of " + yara_name + " in " + tx_loc + '\n'
        T.insert(END, ans)
        add_log(n_out)
        # pass

def inner_search(yara):
    el = os.getcwd()
    # print()
    nel = str(el)
    nel = nel.replace('\\', '/')
    if nel in yara:
        print(nel, yara)
        x = int(len(nel))
        print(x)
        yara_loc = yara[x+1:]
        print(yara[x+1:])
        for tx in os.listdir(search_dir_var):
            # y_com = "yara64 -s -r "
            if tx.__contains__("."):
                if nel in search_dir_var:
                    search_dir_temp = search_dir_var + '/' + tx
                    # print(nel, search_dir_var, x)
                    print(search_dir_temp[x+1:])
                    file_loc = search_dir_temp[x+1:]
                    cmd = "yara64 -s -r " + yara_loc + " " + file_loc
                    # print(cmd)
                    execute_cmd(cmd, yara, tx, search_dir_temp)
                # Prints only text file present in My Folder
                # print(tx)

def search_helper():
    # pass
    global yara_list
    for s in yara_list:
        inner_search(s)
    # s = "yara64 -s -r bl/crime_wannacry.yar bl/wana.exe"
    # l = s.split(' ')

def open_logger():
    webbrowser.open("logs.txt")
    # pass

# def new_window1():
#     " new window"
#     try:
#         if win1.state() == "normal": win1.focus()
#     except NameError as e:
#         print(e)
#         win1 = Toplevel()
#         win1.geometry("300x300+500+200")
#         win1["bg"] = "navy"
#         lb = Label(win1, text="Hello")
#         lb.pack()

def gen_yara():
    " new window"
    try:
        if win.state() == "normal": win.focus()
    except NameError as e:
        def submit_gen():
            text_file = open("template.yar", "r")
            data = text_file.read()
            text_file.close()
            new_file = open("new_yara.yar", "r+")

            data = data.replace("XNAMEX", r_name.get(1.0, "end-1c"))
            
            data = data.replace("XDESCX", desc.get(1.0, "end-1c"))
            data = data.replace("XTLEVELX", threat.get(1.0, "end-1c"))
            temp_str = string_con.get(1.0, "end-1c").split(",")

            tmp = ""
            for i in range(0, min(26, len(temp_str))):
                if i == 0:
                    tmp = "$" + chr(i+97) + " = " + '"' + temp_str[i] + '"'
                else:
                    tmp = tmp + '\t' + '\n' + "$" + chr(i+97) + " = " + '"' + temp_str[i] + '"'


            data = data.replace("XSTRINGX", tmp)
            if len(condit.get(1.0, "end-1c")) != "":
                data = data.replace("XCONX", condit.get(1.0, "end-1c"))
                
            new_file.write(data)
            # data = data.replace('XDESCX', "Temped")
            # data[4] = '#'
            print(data)
            print(type(data))
            # print(r_name.get(1.0, END))
            # print(r_name.get(1.0, "end-1c"))
            webbrowser.open("new_yara.yar")
            win.destroy()
        print(e)
        win = Toplevel()
        win.geometry("550x400")
        # global r_name, desc, threat, string_con, condit, submit_btn
        Label(win, text="Rule Name:", font=2).grid(row = 0, column= 0)
        r_name = Text(win, height = 1, width = 50)
        r_name.grid(row = 0, column= 1)
        Label(win, text="Description:", font=2).grid(row = 1, column= 0)
        desc = Text(win, height = 1, width = 50)
        desc.grid(row = 1, column= 1)
        Label(win, text="Threat Level:", font=2).grid(row = 2, column= 0)
        threat = Text(win, height = 1, width = 50)
        threat.grid(row = 2, column= 1)
        Label(win, text="String to Filter:", font=2).grid(row = 3, column= 0, columnspan=2)
        Label(win, text="Enter strings separated by ',':").grid(row = 4, column= 0, columnspan=2)
        string_con = Text(win, height = 5, width = 60)
        string_con.grid(row = 5, column= 0, columnspan=4, rowspan=3, padx=30)
        # r_name.pack(side= RIGHT, padx=20)
        Label(win, text="Conditions:", font=2).grid(row = 10, column= 0, columnspan=2)
        Label(win, text="Enter alphabets starting from 'a' as first string (Default is OR of all strings):").grid(row = 11, column= 0, columnspan=2)
        condit = Text(win, height = 5, width = 60)
        condit.grid(row = 12, column= 0, columnspan=4, rowspan=2, padx=30)
        submit_btn = ttk.Button(win, text = "CREATE", command = submit_gen).grid(row=15, column=0, columnspan=2, pady=8)

        # desc.pack(side= RIGHT, padx=20)
        
        # win1["bg"] = "navy"

        # lb = Label(win1, text="Hello")
        # lb.pack()

def select_yara_file():
    path = filedialog.askopenfilenames(title="Select Yara Files", filetypes = (("Yara files", "*.yar*"), ("all files", "*.*")))
    # path = filedialog.askopenfilenames(title="Select Yara Files")
    print(path)
    # file_name = ' files chosen'
    # print(type(yara))
    # Label(top_frame, text = file_name, bg='#f00', font=13).pack()
    global yara_chosen
    global no_yara
    global yara_list
    yara_list = list(path)
    no_yara = len(path)
    print(type(path))
    # no_files = pat
    yara_chosen.config(text = str(len(path)) + " Yara files selected")
    # print(type(yara))

#Create a label and a Button to Open the dialog

gen_btn = ttk.Button(top_frame, text = "Generate YARA file", command = gen_yara)
gen_btn.pack(ipadx=5, pady=5)

button= ttk.Button(top_frame, text="Select Directory", command= select_file)
# file_name = '0 files chosen'
# button.grid(column=1, row=2)

button.pack(ipadx=5, pady=15)

# gen_btn = ttk.Button(top_frame, text = "Generate YARA", command = gen_yara)
# gen_btn.pack(side = RIGHT, ipadx=5, pady=15)

button2 = ttk.Button(bot_frame, text="Select YARA Files", command= select_yara_file)
# button3 = ttk.Button(side = RIGHT)
# button2.grid(column=2, row=2)
button2.pack(side=LEFT, padx=20, pady=40)

select_dir = Label(top_frame, text="No Directory Selected", font=13)
select_dir.pack()

yara_chosen = Label(top_frame, text = "0 Yara files selected", fg='#f00', font=13)
yara_chosen.pack()

T = Text(top_frame, height = 12, width = 73)
T.pack(side= TOP, padx=20)
# T.insert(END, "")

log_btn = ttk.Button(bot_frame, text = "Open Logs", command = open_logger)
log_btn.pack(side = LEFT, padx=20)

search_btn = ttk.Button(bot_frame, text = "SEARCH", command = search_helper)
search_btn.pack(side = RIGHT, padx=20)

# gen_btn = ttk.Button(bot_frame, text = "Generate YARA", command = gen_yara)
# gen_btn.pack(pady=50)

root.mainloop()