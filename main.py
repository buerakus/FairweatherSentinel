import sys
import tkinter as tk
from dashboard_ui import DashboardWindow
from dashboard_ui import LoginDialog

def main():
    root = tk.Tk()
    root.withdraw()

    login = LoginDialog(root, title="Login")

    if login.result:
        root.destroy()
        app = DashboardWindow(user_role=login.result["role"])
        app.mainloop()
    else:
        print("[-] Login failed or cancelled.")
        sys.exit(0)

if __name__ == "__main__":
    main()
