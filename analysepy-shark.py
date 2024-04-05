import pyshark
import os
import matplotlib.pyplot as plt
import numpy as np
from datetime import datetime, timedelta


mylabels = ["TLS 1.1", "TLS 1.2/1.3"]

directory="D:/SchuleIngenieur/fsa13ba/Q6/LINFO1341/projet 1"#os.getcwd
path = os.path.join(directory, "4g/exelmodif.pcapng")
'''cap = pyshark.FileCapture(path, display_filter='tls')
versions = {'TLS 1.3':0, 'TLS 1.2': 0, 'TLS 1.0': 0}
contents = {'Application Data':0, 'Change Cipher Spec':0, 'Handshake':0}
for packet in cap:
    try: 
        tls = packet.tls
        record_versions = [field.showname_value.split('(')[0][0:-1] for field in tls.record_version.all_fields]
        for v in record_versions: versions[v] += 1 #TLS 1.2 et 1.3 sont confondues

        content_type = [field.showname_value.split('(')[0][0:-1] for field in tls.record_content_type.all_fields]
        for c in content_type: contents[c] += 1
        hs_types = [field.showname_value.split('(')[0][0:-1] for field in tls.handshake_type.all_fields]

        for hs_idx in range(len(hs_types)):
            
            if hs_types[hs_idx] == 'Certificate':  
                #f.write(f"\t- {hs_types[hs_idx]} - {record_versions[0]}\n") 
                certificates_times = [field.get_default_value() for field in tls.x509af_utctime.all_fields]
                issuers_and_subjects = [field.showname_value.split('=')[1].rstrip(")") for field in tls.x509if_rdnsequence_item.all_fields if 'id-at-commonName' in field.showname_value]
                for cert_idx in range(len(tls.handshake_certificate_length.all_fields)):
            
                    issuer = issuers_and_subjects[2*cert_idx]
                    subject = issuers_and_subjects[2*cert_idx+1]
                    
                    #print(issuer,subject)
    except: continue
#print(versions)
'''

y = np.array([43,3396])

#cap.close()

path1=os.path.join(directory, "wifi/wordmodifimgwifi binome.pcapng")
path2=os.path.join(directory, "wifi/pwp wifi modif.pcapng")
path3=os.path.join(directory, "wifi/excellwifisynchro.pcapng")
path4=os.path.join(directory, "wifi/folder_app.pcapng")

cap1 = pyshark.FileCapture(path)
cap2 = pyshark.FileCapture(path1)
cap3 = pyshark.FileCapture(path2)
cap4 = pyshark.FileCapture(path3)
cap5 = pyshark.FileCapture(path4)
captures=["",cap1,cap2,cap3,cap4,cap5]
l=["Excell","Word Simultaneous","PWP","Excell Simultaneous","folder upload"]
dico={1:{"UDP":0,"TCP":0,"N_Length":0,"Count":0},2:{"UDP":0,"TCP":0,"N_Length":0,"Count":0},3
      :{"UDP":0,"TCP":0,"N_Length":0,"Count":0},4:{"UDP":0,"TCP":0,"N_Length":0,"Count":0},5:{"UDP":0,"TCP":0,"N_Length":0,"Count":0}}
dico_co={1:{"UDP":0,"TCP":0,},2:{"UDP":0,"TCP":0},3
      :{"UDP":0,"TCP":0},4:{"UDP":0,"TCP":0},5:{"UDP":0,"TCP":0}}
temps=[""]
'''for id in range(1,6):
    start_time = None
    end_time = None
    curr_cap=captures[id]
    for packets in curr_cap:
        if 'TCP' in packets:
            dico[id]["TCP"]+=int(packets.length)
            dico_co[id]["TCP"]+=1
        elif 'UDP' in packets:
            dico[id]["UDP"]+=int(packets.length)
            dico_co[id]["UDP"]+=1
        dico[id]["N_Length"]+=int(packets.length)
        dico[id]["Count"]+=1
        if start_time is None:
            start_time = datetime.now()
        end_time = datetime.now()
    temps.append((end_time-start_time).total_seconds())'''

dico1={1: {'UDP': 6038815, 'TCP': 8430529, 'N_Length': 14469344, 'Count': 17865}, 
       2: {'UDP': 10565, 'TCP': 3195964, 'N_Length': 3207403, 'Count': 5288},
       3: {'UDP': 13210295, 'TCP': 15040343, 'N_Length': 28252258, 'Count': 33558}, 
       4: {'UDP': 12371206, 'TCP': 10770113, 'N_Length': 23142365, 'Count': 26903}, 5: 
           {'UDP': 11052, 'TCP': 17783831, 'N_Length': 17796491, 'Count': 14198}}
temps2=[ 44.32836, 16.283765, 131.140746, 104.764839, 62.109134]
dico2={1: {'UDP': 6033, 'TCP': 11832}, 2: {'UDP': 39, 'TCP': 5239}, 
       3: {'UDP': 12904, 'TCP': 20635}, 4: {'UDP': 12164, 'TCP': 14727}, 
       5: {'UDP': 36, 'TCP': 14139}}
l=["Excell","Word Simultaneous","PWP","Excell Simultaneous","folder upload"]
Tp=[]
F=[[],[],[],[],[]]
for id in range(0,5):
    Tp.append(dico1[id+1]['N_Length']/dico1[id+1]['Count'])
    F[id].append(dico1[id+1]['UDP']/temps2[id])
    F[id].append(dico1[id+1]['TCP']/temps2[id])
    F[id].append(100*dico2[id+1]['UDP']/dico1[id+1]['Count'])
    F[id].append(100*dico2[id+1]['TCP']/dico1[id+1]['Count'])
    F[id].append(100*dico1[id+1]['UDP']/dico1[id+1]['N_Length'])
    F[id].append(100*dico1[id+1]['TCP']/dico1[id+1]['N_Length'])
for b in F:
    print(b)
    
    
#print(Tp)
plt.bar(range(len(Tp)),height=Tp, tick_label = l,width = 0.8, color = ['black', 'blue','purple','gray','maroon'])
plt.ylabel("Byte/Packet")
plt.xlabel("scénarios")
#plt.show()


