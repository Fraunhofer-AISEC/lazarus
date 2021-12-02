import tkinter as tk
from enum import Enum
from matplotlib.backends.backend_tkagg import (
    FigureCanvasTkAgg, NavigationToolbar2Tk)
from matplotlib.figure import Figure
import matplotlib.pyplot as plt
import matplotlib.animation as animation
import numpy as np
from random import random
import datetime as dt
from lz_hub_device_certbag import device_certbag
import lz_hub_db
import time

def frm_create_basic_info(window, uuid):

    # Get stuff from database
    db = lz_hub_db.connect()
    name, awdt_period_s, status, index, temperature, humidity = lz_hub_db.get_device_info(db, uuid)
    lz_hub_db.close(db)

    uuid_info =        f"UUID       : {uuid.decode('utf-8')}"
    name_info =        f"Name       : {name}"
    awdt_period_info = f"AWDT Period: {awdt_period_s}s"
    status_info =      f"Status     : {status}"

    basic_info = (uuid_info + "\n" + name_info + "\n" + awdt_period_info + "\n" + status_info)

    frm_basic_info = tk.Frame(master=window)

    lbl_info = tk.Label(master=frm_basic_info, height=6, width=77, text=basic_info, bg="#e8daef",
        anchor='w', justify='left')
    lbl_info.configure(font=('TkFixedFont', ))
    lbl_info.pack()

    return frm_basic_info


def frm_create_device_cert(window, uuid):
    # Access the database and read the certificate
    # TODO GET ALL CERTBAGS
    cb = device_certbag(uuid)

    cb.device_id_cert

    header_device_id_cert = "DeviceID Certificate:"
    header_alias_id_cert = "AliasID Certificate:"

    cert_info = (header_device_id_cert + "\n" + get_cert_info_string(cb.device_id_cert)+ "\n\n" +
    header_alias_id_cert + "\n" + get_cert_info_string(cb.alias_id_cert))

    frm_cert = tk.Frame(master=window)

    lbl_info = tk.Label(master=frm_cert, text=cert_info, height=20, width=77, bg="#e8daef",
        anchor='w', justify='left')
    lbl_info.configure(font=('TkFixedFont', ))
    lbl_info.pack()

    return frm_cert


def read_temp(uuid):
    updated = False
    db = lz_hub_db.connect()
    _, _, _, counter, temperature, _ = lz_hub_db.get_device_info(db, uuid)
    lz_hub_db.close(db)
    if read_temp.counter.get(uuid) is None:
        updated = True
        read_temp.counter[uuid] = 0
    if counter > read_temp.counter[uuid]:
        updated = True
    read_temp.counter[uuid] = counter
    return temperature, updated
read_temp.counter = {}


def read_hum(uuid):
    updated = False
    db = lz_hub_db.connect()
    _, _, _, counter, _, humidity = lz_hub_db.get_device_info(db, uuid)
    lz_hub_db.close(db)
    if read_hum.counter.get(uuid) is None:
        updated = True
        read_hum.counter[uuid] = 0
    if counter > read_hum.counter[uuid]:
        updated = True
    read_hum.counter[uuid] = counter
    return humidity, updated
read_hum.counter = {}



# This function is called periodically from FuncAnimation
def animate(i, ax, xs, ys, uuid, data_func, label):

    # Read temperature (Celsius)
    value, updated = data_func(uuid)

    # Add x and y to lists
    xs.append(dt.datetime.now().strftime('%M:%S'))
    ys.append(value)

    # Limit x and y lists to 20 items
    xs = xs[-10:]
    ys = ys[-10:]

    # Draw x and y lists
    ax.clear()
    ax.set_ylabel(label)
    if updated:
        fmt = 'bo-'
    else:
        fmt = 'r-'
    ax.plot(xs, ys, fmt)


def frm_create_plot(window, uuid, fig_temp, fig_hum):

    frm = tk.Frame(master=window)

    # Temperature
    canvas_temp = FigureCanvasTkAgg(fig_temp, master=frm)
    canvas_temp.draw()
    canvas_temp.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH, expand=1)

    # Humidity
    canvas_hum = FigureCanvasTkAgg(fig_hum, master=frm)  # A tk.DrawingArea
    canvas_hum.draw()
    canvas_hum.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH, expand=1)

    return frm


def frm_create_device_info(window, uuid, fig_temp, fig_hum):

    frm_device_info = tk.Frame(master=window, width=530, height=800)

    frm_basic_info = frm_create_basic_info(frm_device_info, uuid)
    frm_basic_info.pack()

    frm_device_data = frm_create_plot(frm_device_info, uuid, fig_temp, fig_hum)
    frm_device_data.pack()

    frm_cert_info = frm_create_device_cert(frm_device_info, uuid)
    frm_cert_info.pack()

    return frm_device_info


def get_cert_info_string(cert):

    if cert is None:
        print("WARN: Ignoring database entry with invalid certificate")
        return ""

    issuer = cert.get_issuer()
    subject = cert.get_subject()
    val_before = cert.get_notBefore().decode('utf-8')
    val_after = cert.get_notAfter().decode('utf-8')
    val = (         val_before[0:4] + "-" + val_before[4:6] + "-" +  val_before[6:8] + " " +
                    val_before[8:10] + ":" + val_before[10:12] + ":" + val_before[12:14] + "  -  " +
                    val_after[0:4] + "-" + val_after[4:6] + "-" +  val_after[6:8] + " " +
                    val_after[8:10] + ":" + val_after[10:12] + ":" + val_after[12:14])

    # Get subject key identifier and authority key identifier
    subj_ident = "Not available"
    auth_ident = "Not available"
    for i in range(cert.get_extension_count()):
        if b"subjectKeyIdentifier" in cert.get_extension(i).get_short_name():
            subj_ident = cert.get_extension(i).__str__()
        if b"authorityKeyIdentifier" in cert.get_extension(i).get_short_name():
            # "keyId:" is stripped because of space reasons
            auth_ident = cert.get_extension(i).__str__()[6:]

    issuer_info =     f"Issuer     : C = {issuer.C}, ST =  {issuer.ST}, O = {issuer.O}, CN = {issuer.CN}"
    subject_info =    f"Subject    : C = {subject.C}, ST =  {subject.ST}, O = {subject.O}, CN = {subject.CN}"
    val_info =        f"Valid      : {val}"

    subj_ident_info = f"Subj. Ident: {subj_ident}"
    auth_ident_info = f"Auth. Ident: {auth_ident}"

    cert_info = (   issuer_info + "\n" +
                    subject_info + "\n" +
                    val_info + "\n" +
                    subj_ident_info + "\n" +
                    auth_ident_info)

    return cert_info


'''
TEST ONLY
'''


def test():
    window = tk.Tk()

    uuid = b"9900ACFF-352A-4966-BE5B-DF79B5CF825E"

    fig_temp = Figure(figsize=(7, 2), dpi=85)
    fig_hum = Figure(figsize=(7, 2), dpi=85)

    ax_temp = fig_temp.add_subplot(111)
    xs_temp = []
    ys_temp = []

    ax_hum = fig_hum.add_subplot(111)
    xs_hum = []
    ys_hum = []

    frm_device_info = frm_create_device_info(window, uuid, fig_temp, fig_hum)
    frm_device_info.pack()

    ani_temp = animation.FuncAnimation(
        fig_temp,
        animate,
        fargs=(ax_temp, xs_temp, ys_temp, uuid, read_temp,
        "Temp (deg C)"),
        interval=4000)

    ani_hum = animation.FuncAnimation(
        fig_hum,
        animate,
        fargs=(ax_hum, xs_hum, ys_hum, uuid, read_hum,
        "Humidity (%)"),
        interval=4000)

    window.mainloop()


def test_frm_create_plot():
    window = tk.Tk()
    window.wm_title("Lazarus Hub")

    uuid = b"9900ACFF-352A-4966-BE5B-DF79B5CF825E"

    fig_temp = Figure(figsize=(7, 2), dpi=85)
    fig_hum = Figure(figsize=(7, 2), dpi=85)

    ax_temp = fig_temp.add_subplot(111)
    xs_temp = []
    ys_temp = []

    ax_hum = fig_hum.add_subplot(111)
    xs_hum = []
    ys_hum = []

    frm_plot = frm_create_plot(window, uuid, fig_temp, fig_hum)
    frm_plot.pack()

    ani_temp = animation.FuncAnimation(
        fig_temp,
        animate,
        fargs=(ax_temp, xs_temp, ys_temp, uuid, read_temp,
        "Temp (deg C)"),
        interval=1000)

    ani_hum = animation.FuncAnimation(
        fig_hum,
        animate,
        fargs=(ax_hum, xs_hum, ys_hum, uuid, read_hum,
        "Humidity (%)"),
        interval=1000)

    window.mainloop()


def test_frm_create_device_cert():
    window = tk.Tk()
    window.wm_title("Lazarus Hub")

    uuid = b"9900ACFF-352A-4966-BE5B-DF79B5CF825E"

    frm_alias = frm_create_device_cert(window, uuid)
    frm_alias.pack()

    window.mainloop()


def test_read_temp():
    uuid = b"9900ACFF-352A-4966-BE5B-DF79B5CF825E"
    for _ in range(10):
        temp, updated = read_temp(uuid)
        print(f"Temp = {temp}, updated = {updated}")
        time.sleep(1)

def test_read_hum():
    uuid = b"9900ACFF-352A-4966-BE5B-DF79B5CF825E"
    for _ in range(10):
        hum, updated = read_hum(uuid)
        print(f"Hum = {hum}, updated = {updated}")
        time.sleep(1)

# test_frm_create_device_cert()
# test_frm_create_plot()
# test()