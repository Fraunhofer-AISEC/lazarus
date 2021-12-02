import tkinter as tk
from matplotlib.backends.backend_tkagg import (
    FigureCanvasTkAgg, NavigationToolbar2Tk)
from matplotlib.figure import Figure
import matplotlib.animation as animation
import matplotlib.pyplot as plt
import numpy as np
from random import random
import datetime as dt

import gui_hub_info
import gui_device_info
import lz_hub_db
from lz_hub_device_certbag import device_certbag

bg_frame1 = "#a2d9ce"
bg_frame2 = "#e8daef"
bg_frame3 = "#d2b4de"

NUM_DEVICES = 3


def main():

    # Create temperature and humidity graphs for NUM_DEVICES
    fig_temp = [Figure(figsize=(7, 2), dpi=85) for i in range(NUM_DEVICES)]
    ax_temp = [fig_temp[i].add_subplot(111) for i in range(NUM_DEVICES)]
    xs_temp = [[] for i in range(NUM_DEVICES)]
    ys_temp = [[] for i in range(NUM_DEVICES)]

    fig_hum = [Figure(figsize=(7, 2), dpi=85) for i in range(NUM_DEVICES)]
    ax_hum = [fig_hum[i].add_subplot(111) for i in range(NUM_DEVICES)]
    xs_hum = [[] for i in range(NUM_DEVICES)]
    ys_hum = [[] for i in range(NUM_DEVICES)]

    window = tk.Tk()

    '''
    FRAME 1: Caption
    '''

    frame1 = tk.Frame(master=window, width=1000, height=100, bg=bg_frame1)
    frame1.pack(side=tk.TOP, fill=tk.X)

    label = tk.Label(master=frame1, text="Lazarus Hub", bg=bg_frame1)
    label.config(font=("TkDefaultFont", 30))
    label.pack()

    '''
    FRAME 2: Hub Info
    '''

    frm_hub_cert = gui_hub_info.frm_create_hub_cert(window)
    frm_hub_cert.pack(fill=tk.X)

    '''
    FRAME 3: Devices
    '''

    # Retrieve devices from database
    db = lz_hub_db.connect()
    uuids = lz_hub_db.get_uuids(db)
    lz_hub_db.close(db)

    # Currently, just the first NUM_DEVICES UUIDs are displayed
    # TODO: Clean solution
    uuids = uuids[0:NUM_DEVICES]

    frame3 = tk.Frame(master=window, width=1000, height=680, bg=bg_frame3)
    frame3.pack(side=tk.TOP)

    ani_temp = []
    ani_hum = []
    for i in range(min(len(uuids), NUM_DEVICES)):
        window.columnconfigure(i, weight=1, minsize=300)
        window.rowconfigure(i, weight=1, minsize=300)

        frm_device_info = gui_device_info.frm_create_device_info(frame3, uuids[i], fig_temp[i],
            fig_hum[i])

        ani_temp.append(
            animation.FuncAnimation(
                fig_temp[i],
                gui_device_info.animate,
                fargs=(ax_temp[i], xs_temp[i], ys_temp[i], uuids[i], gui_device_info.read_temp,
                "Temp (deg C)"),
                interval=4000))

        ani_hum.append(
            animation.FuncAnimation(
                fig_hum[i],
                gui_device_info.animate,
                fargs=(ax_hum[i], xs_hum[i], ys_hum[i], uuids[i],
                gui_device_info.read_hum,
                "Humidity (%)"),
                interval=4000))

        frm_device_info.grid(row=0, column=i, padx=5, pady=5)

    window.mainloop()


if __name__ == "__main__":
    main()