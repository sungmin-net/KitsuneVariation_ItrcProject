path = "../../dataset/IOT_NETWORK_INTRUSION_DATASET/dos-synflooding-1-dec.pcap"
resultFile = open(path.replace('.pcap', '_result.tsv'), 'r')
maxRmseLine = ['0', '0', '0']
while True:
    line = resultFile.readline()
    if not line : break
    lineSplit = line.strip().split('\t')
    packetNo = lineSplit[0]
    rmse = lineSplit[1]
    label = lineSplit[2]
    #print(lineSplit)
    if rmse > maxRmseLine[1]:
        maxRmseLine = line

print(maxRmseLine)
