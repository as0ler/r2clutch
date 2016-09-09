#!/usr/bin/python

##LGPL - Copyright 2016 - murphy

import os, sys
import shutil
from shutil import copyfile
import r2pipe
import time

def banner():
  print """
  ***************************************************
  *      ____    ___ _       _       _              *
  *  _ _|___ \  / __\ |_   _| |_ ___| |__           *
  * | '__|__) |/ /  | | | | | __/ __| '_ \          *
  * | |  / __// /___| | |_| | || (__| | | |         *
  * |_| |_____\____/|_|\__,_|\__\___|_| |_|         *
  ***************************************************
  """
FAT_MAGIC = '0xcafebabe'
FAT_CIGAM = '0xbebafeca'
MH_MAGIC_64 = '0xfeedfacf'
MH_CIGAM_64 = '0xcffaedfe'
SIZEOF_FAT_ARCH = 20
SIZEOF_FAT_HEADER = 8

applicationPath = "/User/Containers/Bundle/Application"
workingDir = "/var/tmp/r2clutch/"
tmpDir = "/var/tmp/p/"

applications = []

def listApps ():
  containers = os.listdir( applicationPath )
  for container in containers:
    files = os.listdir(applicationPath + "/" + container)
    for file in files:
      filename, ext = os.path.splitext(file)
      if ".app" in ext:
        appname = filename
        application = {
          'name': appname.replace(" ","_"),
          'appid': container,
          'binpath': applicationPath + "/" + container + "/" + file + "/" + appname,
        }
        applications.append(application)


def parseCpu (cputype):
  if cputype == "0x0000000c":
    return 'arm32'
  elif cputype == "0x0100000c":
    return 'arm64'
  else:
    return None


def parseCpuSub (cpusubtype):
  if cpusubtype == "0x00000009":
    return 'armv7'
  elif cpusubtype == "0x00000010":
    return 'armv7f'
  elif cpusubtype == "0x00000011":
      return 'armv7s'
  elif cpusubtype == "0x00000012":
      return 'armv7k'
  elif cpusubtype == "0x00000003":
    return 'armv8'
  elif cpusubtype == "0x00000014":
      return 'arm6m'
  elif cpusubtype == "0x00000015":
      return 'armv7m'
  elif cpusubtype == "0x00000016":
      return 'armv7em'
  elif cpusubtype == "0x00000000":
    return 'armv64_all'
  elif cpusubtype == "0x00000001":
    return 'armv64_v8'
  else:
    return None


def isFatMach0 (r2):
  magic = r2.cmd('pxW 4 @ 0x00~:[1]')
  return (magic == FAT_MAGIC or magic == FAT_CIGAM)


def parseFatMach0 (r2):
  #Read the fat_header struct, which is always in big endian.
  r2.cmd('e cfg.bigendian=true')
  archs = []
  narchs = int(r2.cmd('pxW 4 @ 0x04~:[1]'), 0)
  i=0
  offset = SIZEOF_FAT_HEADER
  while i < narchs:
    offset += SIZEOF_FAT_ARCH * i
    arch = {}
    arch['cputype'] = parseCpu(r2.cmd('pxW 4 @ ' + str(offset) + '+ 0~:[1]'))
    arch['cpusubtype'] = parseCpuSub(r2.cmd('pxW 4 @ ' + str(offset) + '+ 4~:[1]'))
    arch['offset'] = r2.cmd('pxW 4 @ ' + str(offset) + '+ 8~:[1]')
    arch['size'] = r2.cmd('pxW 4 @ ' + str(offset) + '+12~:[1]')
    archs.append(arch)
    i+=1
  r2.cmd('e cfg.bigendian=false')
  return archs


def Mach0_get_bits (r2):
  magic = r2.cmd('pxW 4 @ 0x00~0x00:[1]')
  if magic == MH_MAGIC_64 or magic == MH_CIGAM_64:
    return 64
  else: 
    return 16


def getInfoMach0 (r2, app, sdb=False):
  binInfo = {}
  #Getting info from SDB
  if sdb:
    #r2 = r2pipe.open(app, ['-e bin.strings=false'])
    #Remove all fd's
    r2.cmd('o-*')
    #Open app with Rbin info
    r2.cmd('o '+app)
    encrypted = r2.cmd('k bin/cur/info/cryptid')
    binInfo['cryptheader'] = r2.cmd('k bin/cur/info/cryptheader').rstrip('\n')
    binInfo['cryptoff'] = r2.cmd('k bin/cur/info/cryptoff').rstrip('\n')
    binInfo['cryptsize'] = r2.cmd('k bin/cur/info/cryptsize').rstrip('\n')
    binInfo['bits'] = r2.cmd('i~bits:[1]').rstrip('\n')
  #Getting info from HDR
  else:
    #r2 = r2pipe.open(app, ['-nn'])
    r2.cmd('o-*')
    r2.cmd('on ' + app) 
    cmd = r2.cmd('pxW 4 @ mach0_cmd_11~:[1]')
    #Load command 11/12 = LC_ENCRYPTION = 0x21
    #Load command 11/12 = LC_ENCRYPTION_64 = 0x2c
    if cmd == '0x00000021' or cmd == '0x0000002c':
      r2.cmd('s mach0_cmd_11')
    else:
      r2.cmd('s mach0_cmd_12')
    encrypted = int(r2.cmd('pxW 4 @ $$+16~:[1]'),0)
    binInfo['cryptheader'] = r2.cmd('?v $$').rstrip('\n')
    binInfo['cryptoff'] = r2.cmd('pxW 4 @ $$+8~:[1]').rstrip('\n')
    binInfo['cryptsize'] = r2.cmd('pxW 4 @ $$+12~:[1]').rstrip('\n')
    binInfo['bits'] = str(Mach0_get_bits (r2))
  if not encrypted:
      print "[X] Ouch! Binary already decrypted!"
      r2.quit()
      clean ()
      exit(0)
  print "[+] Binary encrypted"
  print "[+] Getting  Crypto information:" 
  print "\t[*] Crypto header @ " + binInfo['cryptheader']
  print "\t[*] Crypto offset  @ " + binInfo['cryptoff']
  print "\t[*] Size of the encrypted data: " + binInfo['cryptsize']
  return binInfo


def dumpBin (app, binInfo):
  bits = binInfo['bits']
  print "[+] Attaching a debuger to " + app + "(" + bits + ")"
  r2 = r2pipe.open(app,['-d', '-e bin.classes=false', '-e bin.strings=false', '-b '+bits])
  #Reopen the current binary in debug
  #TODO: r2.cmd("ood")
  r2.cmd("f cryptoff="+binInfo['cryptoff'])
  r2.cmd("f cryptsize="+binInfo['cryptsize'])	
  r2.cmd("f cryptheader="+binInfo['cryptheader'])
  r2.cmd("f baseaddr=`dm~r-x:0[2]`")
  print "[+] Binary loaded @ " + r2.cmd("f~baseaddr:0[0]")
  r2.cmd("s baseaddr")
  r2.cmd("s+cryptoff")
  print "[+] Decrypted section dump => " + r2.cmd("?v baseaddr+cryptoff").rstrip('\n') + " - " + r2.cmd("?v baseaddr+cryptoff+cryptsize").rstrip('\n')
  r2.cmd("wt " + tmpDir + "dump.bin cryptsize")
  r2.quit()

def patchBin (r2, binpath, appname, binInfo):
  print "[+] Clonning the binary"
  if not os.path.exists(workingDir):
    os.makedirs(workingDir)
  outputfile = workingDir + appname 
  copyfile(binpath, outputfile)
  print "[+] Generating the output file @ " + outputfile
  #r2 = r2pipe.open(outputfile, ['-w','-nn'])
  #Reopen the current binary read-write, without rbin info and with headers flags
  r2.cmd('o-*')
  r2.cmd("o+ " + outputfile)
  r2.cmd("f cryptoff="+binInfo['cryptoff'])
  r2.cmd("f cryptheader="+binInfo['cryptheader'])
  r2.cmd("f binoff="+binInfo['binoff'])
  print "[+] Load Mach0 binary at address "+ binInfo['binoff'] 
  r2.cmd("s binoff");
  r2.cmd("s+cryptoff");
  print "[+] Writing decrypted section at " + r2.cmd("?v $$").rstrip('\n') + " (bin offset + crypt offset)"
  r2.cmd("wf " + tmpDir + "dump.bin")
  r2.cmd("s binoff + cryptheader + 16")
  print "[+] Overwriting cryptid byte @ " + r2.cmd("?v $$").rstrip('\n')
  r2.cmd("wx 00")


def clean ():
  print "[+] Cleaning environment"
  if os.path.exists(tmpDir):
    shutil.rmtree(tmpDir)


if __name__ == "__main__":
  banner ()
  listApps ()
  print "[*] Select the application to decrypt"
  i = 0
  for app in applications:
    print "\t["+ str(i) +"] " + app['name'] + " (" + app['appid'] + ") "
    i+=1
  print "\n"
  selectedApp = int(raw_input("Please enter the app number: "))

  if not os.path.exists(tmpDir):
    os.makedirs(tmpDir)

  print "[+] Decrypting application => " + applications[selectedApp]['name']
  print "[+] Opening the binary => " + applications[selectedApp]['binpath']
  r2 = r2pipe.open(applications[selectedApp]['binpath'], ['-nn', '-e bin.classes=false', '-e bin.strings=false'])

  if isFatMach0 (r2):
    print "[+] FatMach0 detected"
    archs = parseFatMach0(r2)
    i = 0
    for arch in archs:
      print "\t["+ str(i) +"] " + arch['cputype'] + " - " + arch['cpusubtype'] + " size: " + arch['size'] + " offset: " + arch['offset']
      i+=1
    if len(archs) > 1:
      print "[*] Select the architecture:"
      selectedArch = int(raw_input("Please enter the app number: "))
    else:
      selectedArch = 0
    print "[+] Extracting Mach0 file "+ archs[selectedArch]['cputype'] +" at offset " + archs[selectedArch]['offset']
    r2.cmd('s ' + archs[selectedArch]['offset'])
    binpath = tmpDir + applications[selectedApp]['name'] + "." + archs[selectedArch]['cputype'] + '.bin'
    r2.cmd('wt '+ binpath + ' ' + archs[selectedArch]['size'])
    start_time = time.time()
    #Bin Info from extracted Bin
    binInfo = getInfoMach0 (r2, binpath)
    binInfo['binoff'] = archs[selectedArch]['offset']
    #Dump decrypted App
    dumpBin (applications[selectedApp]['binpath'], binInfo)
    #Patching FatMach0 file
    patchBin (r2, applications[selectedApp]['binpath'], applications[selectedApp]['name'], binInfo)
  else:
    print "[+] Mach0 detected"
    start_time = time.time()
    binInfo = getInfoMach0 (r2, applications[selectedApp]['binpath'])
    #Bin Info from Mach0 Bin
    binInfo['binoff'] = '0x00000000'
    #Dump decrypted App
    dumpBin (applications[selectedApp]['binpath'], binInfo)
    #Patching Mach0 
    patchBin (r2, applications[selectedApp]['binpath'], applications[selectedApp]['name'], binInfo)

  print("--- %s seconds ---" % (time.time() - start_time))  
  print "[+] File decrypted succesfully!"
  clean ()
  print r2.cmd('fortunes')

  r2.quit()
  exit (0)
