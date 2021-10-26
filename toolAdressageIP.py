from tkinter import *
from tkinter import font
from tkinter import messagebox
import re

"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
Tool permettant de calculer les informations d'un réseau pour le SISR.
----------------------------------------------------------------------
Structure du programme:
* Une classe Reseau qui reçois des adresses IP ou réseau et son masque
  et retourne un objet avec toutes les informations.
* OutputParser qui va organiser ces informations pour les rendre lisibles
* InterfaceFunctions: fontions liés à l'interface graphique
* InterfaceGraphique Tkinter
----------------------------------------------------------------------
Version = 1.0
Python version: 3.XX
Author: Mimoun,  13/10/2021
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

tool_ver = 1.0


# region classe Reseau
def get_adresse_reseau(adresse_ip, masque_reseau):
	"""
	Reçois une adresse ip et un masque, il applique un ET logique et retourne le résultat sous forme de string
	"""
	adresse_reseau = [0, 0, 0, 0]
	for i in range(3):
		adresse_reseau[i] = int(adresse_ip.split('.')[i]) & int(masque_reseau.split('.')[i])  # Réalisation d'un ET logique sur l'adresse ip et le masque.
	return ''.join([str(i) + '.' for i in adresse_reseau])[:-1]  # return adresse_reseau => list(int)

def get_masque_from_cidr(adresse_ip, adresse_reseau):
	"""
	Reçois une adresse ip et une adresse réseau, un des deux peut être (None)
	et retourne le masque
	"""
	octet = 8  											# Taille du chunk qui va repartir les bits en groupe d'octet
	if adresse_ip == None:  							# Si l'utilisateur à introduit uniquement l'adresse réseau
		raw_bin = ('1' * int(adresse_reseau[-2:].replace('/', ''))).ljust(32, '0')  # raw_bin => liste d'octets
		return ''.join([str(int(raw_bin[i:i+octet], 2)) + '.' for i in range(0, len(raw_bin), octet)])[:-1]  # parsed mask
	else:												# Si l'utilisateur à introduit uniquement l'adresse ip
		raw_bin = ('1' * int(adresse_ip[-2:].replace('/', ''))).ljust(32, '0')  # raw_bin => liste d'octets
		return ''.join([str(int(raw_bin[i:i+octet], 2)) + '.' for i in range(0, len(raw_bin), octet)])[:-1]  # parsed mask

def get_broadcast(adresse_reseau, masque):
	masque = [255 - int(octet) for octet in masque.split('.')]  # Inversion du masque
	adresse_reseau = [int(octet) for octet in adresse_reseau.split('.')]
	
	broadcast = zip(masque, adresse_reseau)  # compression de deux listes sous une liste 
	broadcast = [m + a for (m, a) in broadcast]

	return ''.join([str(i) + '.' for i in broadcast])[:-1]
	

def get_premiere_machine(adresse_reseau):
	num = str(int(adresse_reseau[adresse_reseau.rfind('.') + 1:]) + 1)
	return adresse_reseau[:adresse_reseau.rfind('.') + 1] + num

def get_derniere_machine(broadcast):
	num = str(int(broadcast[broadcast.rfind('.') + 1:]) - 1)
	return broadcast[:broadcast.rfind('.') + 1] + num

def get_nombre_machines(masque):
	bits_hote = ''.join([bin(int(i))[2:].ljust(8, '0') for i in masque.split('.')]).count('0')
	return str(2 ** bits_hote - 2)


# Classe 'Reseau' doit reçevoir comme paramètre obligatoire
# une adresse reseau ou un masque, qui peut etre defini soit
# en notation decimale pointé soit avec le cidr '/', si un
# paramètre manque alors => eg: adresse_ip = None
class Reseau:
	def __init__(self, **kwargs):
		self.adresse_reseau = kwargs['adresse_reseau']            # Eg: 192.168.10.0
		self.masque = kwargs['masque']          		          # Eg: 255.255.255.192
		self.adresse_reseau_cidr = kwargs['adresse_reseau_cidr']  # Eg: 192.168.10.0/26
		self.adresse_ip = kwargs['adresse_ip']					  # Eg: 192.168.10.65
		self.adresse_ip_cidr = kwargs['adresse_ip_cidr']	      # Eg: 192.168.10.65/26

		# Si l'utilisateur introduit une adresse_ip + masque mais pas d'adresse reseau
		if self.adresse_reseau == None and self.adresse_ip != None and self.masque != None:
			self.adresse_reseau = get_adresse_reseau(self.adresse_ip, self.masque)
		# Si l'utilisateur utilise la notation cidr avec le réseau ou une ip
		elif self.adresse_reseau_cidr != None and self.adresse_ip_cidr != None:
			self.adresse_ip = self.adresse_ip_cidr[:-(len(self.adresse_ip_cidr) - self.adresse_ip_cidr.index('/'))]
			self.adresse_reseau = self.adresse_reseau_cidr[:-(len(self.adresse_reseau_cidr) - self.adresse_reseau_cidr.index('/'))]
			self.masque = get_masque_from_cidr(self.adresse_ip_cidr, self.adresse_reseau_cidr)
		elif self.adresse_reseau_cidr != None:
			self.adresse_reseau = self.adresse_reseau_cidr[:-(len(self.adresse_reseau_cidr) - self.adresse_reseau_cidr.index('/'))]
			self.masque = get_masque_from_cidr(self.adresse_ip_cidr, self.adresse_reseau_cidr)
		elif self.adresse_ip_cidr != None:
			self.adresse_ip = self.adresse_ip_cidr[:-(len(self.adresse_ip_cidr) - self.adresse_ip_cidr.index('/'))]
			self.masque = get_masque_from_cidr(self.adresse_ip_cidr, self.adresse_reseau_cidr)
			self.adresse_reseau = get_adresse_reseau(self.adresse_ip, self.masque)
		
		self.broadcast = get_broadcast(self.adresse_reseau, self.masque)
		self.premiere_machine = get_premiere_machine(self.adresse_reseau)
		self.derniere_machine = get_derniere_machine(self.broadcast)
		self.hotes = get_nombre_machines(self.masque)
# endregion classe Reseau


# region OutputParser
def get_reseau_info(**kwargs):
    """
    Traite l'input de l'utilisateur et retourne un objet (Reseau) avec les informations calculés
    """
    if kwargs['using_cidr']:
        if len(kwargs['adresse_ip']) == 0:
            reseau = Reseau(adresse_reseau=None, masque=None, adresse_reseau_cidr=kwargs['adresse_reseau'], adresse_ip=None, adresse_ip_cidr=None)
        elif len(kwargs['adresse_reseau']) == 0:
            reseau = Reseau(adresse_reseau=None, masque=None, adresse_reseau_cidr=None, adresse_ip=None, adresse_ip_cidr=kwargs['adresse_ip'])
    else:
        reseau = Reseau(adresse_reseau=None, masque=kwargs['masque'], adresse_reseau_cidr=None, adresse_ip=kwargs['adresse_ip'], adresse_ip_cidr=None)
    return reseau    


def parse_info(**kwargs):
    reseau = get_reseau_info(using_cidr=kwargs['using_cidr'], adresse_ip=kwargs['adresse_ip'], 
        adresse_reseau=kwargs['adresse_reseau'], masque=kwargs['masque'])
    
    info = (f"================================\n"
            f"Adresse IP: {reseau.adresse_ip}\n"
            f"Adresse Réseau: {reseau.adresse_reseau}\n"
            f"Masque: {reseau.masque}\n"
            f"Broadcast: {reseau.broadcast}\n"
            f"Nombre d'hôtes: {reseau.hotes}\n"
            f"Première machine: {reseau.premiere_machine}\n"
            f"Dernière machine: {reseau.derniere_machine}\n"
            f"================================\n"
    )

    return info
# endregion OutputParser


# region InterfaceFunctions
def show_credits():
    messagebox.showinfo('Credits', message="Tool crée par Mimoun pour le BTS SIO.\nLycée Theodore Aubanel 2021.")
# endregion InterfaceFunctions


# region InterfaceGraphique
root = Tk()

# Configuration de la fênetre principale
root.title(f"Tool d'Adressage IP v{str(tool_ver)}")

try:
        root_icon = PhotoImage(file='icon.png')
        root.iconphoto(False, root_icon)
except Exception as ex:          # Image non trouvée
        pass

root.resizable(width=False, height=False)

# User input verif
valid_ip = "^(?:25[0-5]|2[0-4]\d|[0-1]?\d{1,2})(?:\.(?:25[0-5]|2[0-4]\d|[0-1]?\d{1,2})){3}$"
valid_ip_cidr = "^(?:(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/(?:3[0-2]|[12]*\d),)*(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/(?:3[0-2]|[12]*\d)$"
valid_mask = "^(255)\.(0|128|192|224|240|248|252|254|255)\.(0|128|192|224|240|248|252|254|255)\.(0|128|192|224|240|248|252|254|255)"

def check_input(adresse_ip, adresse_reseau, masque):
    global is_cidr
    if re.search(valid_ip_cidr, adresse_ip) or re.search(valid_ip_cidr, adresse_reseau):  # IP ou Réseau en CIDR valide donc pas besoin du masque en decimal pointé
        masque_entry.config(state='disabled')
        calc_button.config(state='normal')
        is_cidr = True
    elif re.search(valid_ip_cidr, adresse_ip) and re.search(valid_ip_cidr, adresse_reseau):  # IP ET Réseau en CIDR valide
        pass
    elif re.search(valid_mask, masque_entry.get()) and re.search(valid_ip, adresse_ip):
        calc_button.config(state='normal')
        is_cidr = False
    else:
        calc_button.config(state='disabled')
        masque_entry.config(state='normal')
# END User input verif

# Variables statiques de style
button_font = font.Font(family='Montserrat', size=12)
label_font = font.Font(family='Monteserrat', size=14)
entry_font = font.Font(family='Helvetica', size=13, weight='bold')
text_font = font.Font(family='Consolas', size=13, weight='bold')


# Configuration du frame principal
mainframe = Frame(root)
mainframe.config(height='500', width='500')
mainframe.pack()

# Menu
menubar = Menu(root)  # Le menu est high-level, donc attaché au root et pas mainframe 
menubar.add_command(label='Info', command=show_credits)
root.config(menu=menubar) 
# END Menu

# Labels
adresse_ip_label = Label(mainframe, text='Adresse IP:')
adresse_ip_label['font'] = label_font
adresse_ip_label.grid(row=0, column=0, sticky='E')

adresse_reseau_label = Label(mainframe, text='Adresse réseau:')
adresse_reseau_label['font'] = label_font
adresse_reseau_label.grid(row=1, column=0, sticky='E')

masque_label = Label(mainframe, text='Masque:')
masque_label['font'] = label_font
masque_label.grid(row=2, column=0, sticky='E')
# END Labels

# Text changed events (vont s'executer à chaque fois pour vérifier l'input de l'utilisateur)
def callback_adresse_ip():
    check_input(adresse_ip_entry.get(), adresse_reseau_entry.get(), masque_entry.get())

def callback_adresse_reseau():
    check_input(adresse_ip_entry.get(), adresse_reseau_entry.get(), masque_entry.get())

def callback_masque():
    check_input(adresse_ip_entry.get(), adresse_reseau_entry.get(), masque_entry.get())

adresse_ip_input = StringVar()
adresse_reseau_input = StringVar()
masque_input = StringVar()

masque_input.trace("w", lambda name, index, mode, masque_input=masque_input: callback_masque())
adresse_ip_input.trace("w", lambda name, index, mode, adresse_ip_input=adresse_ip_input: callback_adresse_ip())
adresse_reseau_input.trace("w", lambda name, index, mode, adresse_reseau_input=adresse_reseau_input: callback_adresse_reseau())
# END Text changed events

# Entries
adresse_ip_entry = Entry(mainframe, width=14, textvariable=adresse_ip_input)
adresse_ip_entry.grid(row=0, column=1)
adresse_ip_entry['font'] = entry_font

adresse_reseau_entry = Entry(mainframe, width=14, textvariable=adresse_reseau_input)
adresse_reseau_entry.grid(row=1, column=1)
adresse_reseau_entry['font'] = entry_font

masque_entry = Entry(mainframe, width=14, textvariable=masque_input)
masque_entry.grid(row=2, column=1)
masque_entry['font'] = entry_font
# END Entries

# Text
output_text = Text(mainframe, width=34, height=10)
output_text.grid(row=4 ,columnspan=2, rowspan=2)
output_text['font'] = text_font
# END Text

# Buttons
def show_info():
    output_text.delete('1.0', END)
    output_text.insert(INSERT, parse_info(using_cidr=is_cidr, adresse_ip=adresse_ip_entry.get(), 
    adresse_reseau=adresse_reseau_entry.get(), masque=masque_entry.get()))

calc_button = Button(mainframe, text='Calculer', width=10, state='disabled', command= lambda: show_info())
calc_button.grid(row=3, column=0, columnspan=2)
calc_button['font'] = button_font
# END Buttons
# endregion InterfaceGraphique

root.mainloop()
