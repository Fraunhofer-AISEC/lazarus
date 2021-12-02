import tkinter as tk
from enum import Enum

from OpenSSL import crypto
import open_ssl_wrapper as osw
import lz_hub_certbag

def frm_create_hub_cert(window):

    # TODO absolute path
    cert_path = "/home/simon/repos/lazarus/lz_hub/certificates"

    # TODO this includes also the private key, which is not needed in this module
    cb = lz_hub_certbag.hub_certbag(cert_path)
    cb.load()

    issuer = cb.hub_cert.get_issuer()
    subject = cb.hub_cert.get_subject()
    val_before = cb.hub_cert.get_notBefore().decode('utf-8')
    val_after = cb.hub_cert.get_notAfter().decode('utf-8')
    val =       (   val_before[0:4] + "-" + val_before[4:6] + "-" +  val_before[6:8] + " " +
                    val_before[8:10] + ":" + val_before[10:12] + ":" + val_before[12:14] + "  -  " +
                    val_after[0:4] + "-" + val_after[4:6] + "-" +  val_after[6:8] + " " +
                    val_after[8:10] + ":" + val_after[10:12] + ":" + val_after[12:14])

    # Get subject key identifier and authority key identifier
    subj_ident = "Not available"
    auth_ident = "Not available"
    for i in range(cb.hub_cert.get_extension_count()):
        if b"subjectKeyIdentifier" in cb.hub_cert.get_extension(i).get_short_name():
            subj_ident = cb.hub_cert.get_extension(i).__str__()
        if b"authorityKeyIdentifier" in cb.hub_cert.get_extension(i).get_short_name():
            # "keyId:" is stripped because of space reasons
            auth_ident = cb.hub_cert.get_extension(i).__str__()[6:]

    issuer_info =     f"Issuer     : C = {issuer.C}, ST =  {issuer.ST}, O = {issuer.O}, CN = {issuer.CN}"
    subject_info =    f"Subject    : C = {subject.C}, ST =  {subject.ST}, O = {subject.O}, CN = {subject.CN}"
    val_info =        f"Valid From : {val}"

    subj_ident_info = f"Subj. Ident: {subj_ident}"
    auth_ident_info = f"Auth. Ident: {auth_ident}"

    cert_info = (   "Hub Certificate:" + "\n" +
                    issuer_info + "\n" +
                    subject_info + "\n" +
                    val_info + "\n" +
                    subj_ident_info + "\n" +
                    auth_ident_info)

    # TODO real data
    hub_version_info = "Hub Version     : v0.0.1"
    hub_uptime_info =  "Hub uptime      : 18:05:42 up 3 days, 7:14 (JUST A DUMMY)"
    hub_dummy_data =   "More dummy data : blablabla"

    hub_info = hub_version_info + "\n" + hub_uptime_info + "\n" + hub_dummy_data

    frm_cert = tk.Frame(master=window)

    frm_cert_info = tk.Frame(master=frm_cert)
    frm_cert_header = tk.Frame(master=frm_cert, bg="#e8daee")

    frm_details = tk.Frame(master=frm_cert_info)
    frm_hub_info = tk.Frame(master=frm_cert_info)

    lbl_header = tk.Label(master=frm_cert_header, text="Lazarus Hub Info", width=120, bg="#a2d9ce", anchor='w', justify='left')
    lbl_header.configure(font=('TkDefaultFont', '18'))
    lbl_header.pack(pady=10, fill=tk.X)

    lbl_info = tk.Label(master=frm_details, text=cert_info, height=6, width=100, bg="#e8daef", anchor='nw', justify='left')
    lbl_info.configure(font=('TkFixedFont', ))
    lbl_info.pack(fill=tk.X)

    lbl_cert = tk.Label(master=frm_hub_info, text=hub_info, height=6, width=100, bg="#e8daef", anchor='nw', justify='left')
    lbl_cert.configure(font=('TkFixedFont', ))
    lbl_cert.pack(fill=tk.X)

    frm_hub_info.pack(side=tk.LEFT, expand=True, fill=tk.X)
    frm_details.pack(side=tk.LEFT, expand=True, fill=tk.X)

    frm_cert_header.pack(fill=tk.BOTH)
    frm_cert_info.pack(fill=tk.X)

    return frm_cert





def test():
    window = tk.Tk()
    window.wm_title("Lazarus Hub")

    frm_cert = frm_create_hub_cert(window)
    frm_cert.pack()

    window.mainloop()


# test()