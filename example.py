from Kitsune import Kitsune
import numpy as np
import time

##############################################################################
# Kitsune a lightweight online network intrusion detection system based on an ensemble of autoencoders (kitNET).
# For more information and citation, please see our NDSS'18 paper: Kitsune: An Ensemble of Autoencoders for Online Network Intrusion Detection

# This script demonstrates Kitsune's ability to incrementally learn, and detect anomalies in recorded a pcap of the Mirai Malware.
# The demo involves an m-by-n dataset with n=115 dimensions (features), and m=100,000 observations.
# Each observation is a snapshot of the network's state in terms of incremental damped statistics (see the NDSS paper for more details)

#The runtimes presented in the paper, are based on the C++ implimentation (roughly 100x faster than the python implimentation)
###################  Last Tested with Anaconda 3.6.3   #######################

'''
# Load Mirai pcap (a recording of the Mirai botnet malware being activated)
# The first 70,000 observations are clean...
print("Unzipping Sample Capture...")
import zipfile
with zipfile.ZipFile("mirai.zip","r") as zip_ref:
    zip_ref.extractall()
'''

# File location
benign_path = "../../dataset/IOT_NETWORK_INTRUSION_DATASET/benign-dec.pcap"
benign_size = 137396

target_path = "../../dataset/IOT_NETWORK_INTRUSION_DATASET/dos-synflooding-1-dec.pcap" #the pcap, pcapng, or tsv file to process.
packet_limit = np.Inf #the number of packets to process

# KitNET params:
maxAE = 10 #maximum size for any autoencoder in the ensemble layer
FMgrace = 10000 #the number of instances taken to learn the feature mapping (the ensemble's architecture)
ADgrace = 100000 #the number of instances used to train the anomaly detector (ensemble itself)

# Build Kitsune
K = Kitsune(benign_path, target_path, packet_limit,maxAE,FMgrace,ADgrace)

print("Running Kitsune:")
RMSEs = []
i = 0
start = time.time()
# Here we process (train/execute) each individual packet.
# In this way, each observation is discarded after performing process() method.

# parse attack packet numbers
attackPacketNumbers = []

with open(target_path.replace('.pcap', '.attacks.tsv'), 'r') as af:
    while True:
        attackPacketNumber = af.readline().strip().split('\t')[0]
        if not attackPacketNumber: break
        attackPacketNumbers.append(attackPacketNumber)
print("Attack packet size: ", len(attackPacketNumbers))


with open(target_path.replace('.pcap', '_result.tsv'), 'w') as fp:
    while True:
        i+=1
        if i % 1000 == 0:
            print(i)
        rmse = K.proc_next_packet()
        if rmse == -1:
            break
        if i > benign_size:
            RMSEs.append(rmse)
            label = 0
            if str(i - benign_size) in attackPacketNumbers:
                label = 1
            fp.write(f'{i- benign_size}\t{rmse:.10f}\t{label}\n')
    stop = time.time()
    print("Complete. Time elapsed: "+ str(stop - start))

'''
with open(path.replace('.pcap', '_result.csv'), 'w') as fp:
    i = 1 # added
    for v in RMSEs:
        fp.write(f'{i}\t{v}\n') # modified
        i += 1 # added
'''
