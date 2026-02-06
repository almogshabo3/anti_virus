import requests
import tkinter as tk
import time


url = "https://www.virustotal.com/api/v3/files"

file_path = r"C:\Users\User\Documents\antivirus\abcdefghi.zip"
headers = {
    "accept": "application/json",
    "x-apikey": "e682f7653b9456e208ac6b4360f7575dc76c2c158add237f41268838fb68c0fe"
}

with open(file_path, "rb") as f:
    upload = requests.post(
        "https://www.virustotal.com/api/v3/files",
        files={"file": f},
        headers=headers
    )
response = upload.json()

if "data" not in response:
    print("שגיאה בהעלאת הקובץ:")
    print(response)
    exit()

analysis_id = response["data"]["id"]
while True:
    result = requests.get(
        f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",headers=headers).json()

    attrs = result["data"]["attributes"]
    status = attrs["status"]

    if status == "completed":
        break

    time.sleep(5)

stats = attrs["stats"]
malicious = stats["malicious"]

print("STATS:", stats)


stats = result["data"]["attributes"]["stats"]

if "attributes" in result["data"] and "stats" in result["data"]["attributes"]:
    malicious = stats["malicious"]

    root = tk.Tk()
    root.title("Scan Result")
    root.geometry("400x200")
    root.configure(bg="#272626")

    title = tk.Label(root, text=" Scan Result", font=("Arial", 18, "bold"), bg="#272626", fg="#0072A7")
    title.pack(pady=20)

    if malicious > 0:
        result_label = tk.Label(root, text=" VIRUS!", font=("Arial", 16, "bold"), fg="red", bg="#1e1e1e")
    else:
        result_label = tk.Label(root, text=" THE FILE IS CLEAN!", font=("Arial", 16, "bold"), fg="lime", bg="#1e1e1e")

    result_label.pack(pady=20)

    root.mainloop()
