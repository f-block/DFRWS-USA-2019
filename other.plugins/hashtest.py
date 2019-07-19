# Copyright (c) 2013 Andrew White <awhite.au@gmail.com>

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details. 
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 
#

#   Hashtest
#   Hash executable content in user space taking into account regions 
#   that potentially change between executions. Requires hashes built
#   with hashbuild.py


import struct
import hashlib
import volatility.commands as commands
import volatility.utils as utils
import volatility.obj as obj
import volatility.debug as debug
import volatility.plugins.taskmods as taskmods
import volatility.plugins.gui.windowstations as windowstations

# VAD permission flags
PROTECT_FLAGS = [
    'PAGE_NOACCESS',
    'PAGE_READONLY',
    'PAGE_EXECUTE',
    'PAGE_EXECUTE_READ',
    'PAGE_READWRITE',
    'PAGE_WRITECOPY',
    'PAGE_EXECUTE_READWRITE',
    'PAGE_EXECUTE_WRITECOPY',
    'PAGE_NOACCESS',
    'PAGE_NOCACHE | PAGE_READONLY',
    'PAGE_NOCACHE | PAGE_EXECUTE',
    'PAGE_NOCACHE | PAGE_EXECUTE_READ',
    'PAGE_NOCACHE | PAGE_READWRITE',
    'PAGE_NOCACHE | PAGE_WRITECOPY',
    'PAGE_NOCACHE | PAGE_EXECUTE_READWRITE',
    'PAGE_NOCACHE | PAGE_EXECUTE_WRITECOPY',
    'PAGE_NOACCESS',
    'PAGE_GUARD | PAGE_READONLY',
    'PAGE_GUARD | PAGE_EXECUTE',
    'PAGE_GUARD | PAGE_EXECUTE_READ',
    'PAGE_GUARD | PAGE_READWRITE',
    'PAGE_GUARD | PAGE_WRITECOPY',
    'PAGE_GUARD | PAGE_EXECUTE_READWRITE',
    'PAGE_GUARD | PAGE_EXECUTE_WRITECOPY',
    'PAGE_NOACCESS',
    'PAGE_WRITECOMBINE | PAGE_READONLY',
    'PAGE_WRITECOMBINE | PAGE_EXECUTE',
    'PAGE_WRITECOMBINE | PAGE_EXECUTE_READ',
    'PAGE_WRITECOMBINE | PAGE_READWRITE',
    'PAGE_WRITECOMBINE | PAGE_WRITECOPY',
    'PAGE_WRITECOMBINE | PAGE_EXECUTE_READWRITE',
    'PAGE_WRITECOMBINE | PAGE_EXECUTE_WRITECOPY',
]


class HashTest(taskmods.DllList, windowstations.WndScan):
    """Hash executable content and compare to known hashes"""
    def __init__(self, config, *args):
        taskmods.DllList.__init__(self, config, *args)
        windowstations.WndScan.__init__(self, config, *args)
        config.add_option('HASHSET', short_option = 's', default = "",
                          help = 'Location of hash set to build or use',
                          action = 'store', type = 'str')
        config.add_option('DUMPDIR', short_option = 'D', default = "",
                          help = 'Location to output suspicious pages',
                          action = 'store', type = 'str')
        self.unverifiable_allocs = []

    def render_text(self, outfd, data):
        if self._config.HASHSET == "":
            debug.error("Error - no hash set specified\n")
        if self._config.DUMPDIR == "":
            debug.error("Error - no dump directory specified\n")

        outfd.write("Testing image against hash set\n")
        string = "\t{0:08x} - Matched {1:05d}/{2:05d} executable | {3:05d} executable data pages | {4}\n"

        # track statistics
        self.verifiable_allocs = 0
        self.unknown_allocs = 0
        self.alloc_total = 0
        #verified pages
        self.page_exec = 0
        self.page_match_exec = 0
        #unverified pages
        self.suspicious = 0
        self.exec_data = 0
        #unknown pages
        self.unknown_pages_exec = 0

        #get pfn data
        self.kernel_space = utils.load_as(self._config)
        kdbg = obj.Object("_KDDEBUGGER_DATA64",
                          offset = obj.VolMagic(self.kernel_space).KDBG.v().v(),
                          vm = self.kernel_space)
        self.pfn_addr = kdbg.MmPfnDatabase.dereference_as("Pointer").v()
        
        # hack
        # command to return this value from profile returns 0x18
        # should be 0x1c with PAE
        # print "{0:08x}".format(kernel_space.profile.get_obj_size("_MMPFN"))
        self.mmpfn_size = 0x1c
        


        #get desktop heaps
        desktop_heap_segments = self.get_desktop_heap_segments()
        for task in data:
            # look at each process
            outfd.write("PID - {0:05d} {1}\n".format(task.UniqueProcessId, task.ImageFileName))
            for start, matches, available, exec_data, filename, is_verifiable, is_present in self.test(task, desktop_heap_segments):
                # output information returned
                # TODO - fix up output format
                if not(is_verifiable):
                    filename += " - (Unverifiable)"
                elif not(is_present):
                    filename += " - (Unknown)"
                outfd.write(string.format(start, matches, available, exec_data, filename))
                # calculate statistics
                self.alloc_total += 1
                if is_present and is_verifiable:
                    self.verifiable_allocs += 1
                    self.page_match_exec += matches
                    self.page_exec += available
                    self.exec_data += exec_data
                else:
                    if is_verifiable:
                        self.unknown_allocs += 1
                        self.unknown_pages_exec += available
                        self.exec_data += exec_data
        outfd.write("\n")

        # Output statistics
        self.page_non_match = self.page_exec - self.page_match_exec - self.exec_data
        outfd.write("Verifiable Allocs   - {0}\n".format(self.verifiable_allocs))
        outfd.write("\tExec Page Total   - {0}\n".format(self.page_exec))
        outfd.write("\tExec Non-Match    - {0}\n".format(self.page_non_match))
        outfd.write("\tExec percentage   - {0:.2f}%\n".format((self.page_exec - self.page_non_match) / (float(self.page_exec) or 1) * 100))
        outfd.write("\tExec Data Page    - {0}\n".format(self.exec_data))
        outfd.write("Unverifiable Allocs - {0}\n".format(len(self.unverifiable_allocs)))
        outfd.write("Unknown Allocs      - {0}\n".format(self.unknown_allocs))
        outfd.write("\tUnknown Exec      - {0}\n".format(self.unknown_pages_exec))


    def ranges(self, task, desktop_heap_segments):
        """Get all executable memory allocations and their names"""
        vads = []
        names = {}
        unverifiable = {}
        special = {}
        ps_ad = task.get_process_address_space()

        # get location of unverifiable allocations
        heap = self.get_shared_heap(task)
        win32k_var = self.get_win32k_var(task, ps_ad)
        winlogon_allocs = self.get_winlogon_allocations(task, ps_ad)

        # TODO - add in checking for accesible pages outside VAD
        for vad in task.VadRoot.traverse():
            # save required information about each allocation
            permissions = vad.u.VadFlags.Protection.v()
            if "EXECUTE" in PROTECT_FLAGS[permissions]:
                start = vad.Start
                end = vad.End
                vads.append([start, end])
                if start in winlogon_allocs:
                    names[start] = "Winlogon EXECUTE_READWRITE allocation"
                    unverifiable[start] = 0
                    continue
                # get names from VAD rather than LDR modules
                # some extra ones in VAD, e.g. system's ntdll.dll
                try:
                    control_area = vad.ControlArea
                    if control_area:
                        file_object = vad.FileObject
                        if file_object:
                            basename = str(file_object.FileName).split("\\")[-1]
                            names[start] = basename.lower()
                        else:
                            segment = control_area.Segment.v()
                            if segment in desktop_heap_segments:
                                names[start] = desktop_heap_segments[segment]
                                unverifiable[start] = segment
                            elif start == heap:
                                names[start] = "Shared Read Only Heap"
                                unverifiable[start] = segment
                            elif segment == win32k_var:
                                names[start] = "Win32k.sys Read Only Data"
                                unverifiable[start] = segment
                except:
                    pass
        # sort allocations by start address                    
        vads = sorted(vads, key=lambda vad: vad[1])
        # save information about unverifiable allocations to allow retrieval  
        for offset, desc in self.get_unverifiable_allocs(task, ps_ad, vads, names):
            unverifiable[offset] = 0
            names[offset] = desc
        for offset, desc in self.get_special_allocs(task, ps_ad, names):
            special[offset] = desc
        return ps_ad, vads, names, unverifiable, special

    def get_win32k_var(self, task, ps_ad):
        """Specifc allocation created by win32k.sys that is unverifiable"""
        # TODO - find a better method of locating
        var = ps_ad.zread(0xbf9aa6dc, 4)
        section = struct.unpack("<L", var)[0]
        section_object = obj.Object("_SECTION_OBJECT", offset=section, vm=ps_ad)
        segment_addr = section_object.Segment.v()
        return segment_addr

    def get_shared_heap(self, task):
        """Get location of shared heap"""
        heap = task.Peb.ReadOnlySharedMemoryBase.v()
        return heap

    def get_desktop_heap_segments(self):
        """Get the segments of the desktop heaps"""
        segments = {}
        for window_station in windowstations.WndScan.calculate(self):
            for desktop in window_station.desktops():
                section_object = desktop.hsectionDesktop.dereference_as("_SECTION_OBJECT")
                segment_addr = section_object.Segment.v()
                segments[segment_addr] = "Desktop Heap - {0}\\{1}".format(desktop.WindowStation.Name, desktop.Name)
        return segments

    def get_winlogon_allocations(self, task, ps_ad):
        """Get the EXECUTE_READWRITE pages used by winlogon"""
        if str(task.ImageFileName) == "winlogon.exe":
            base = task.SectionBaseAddress
            addrs = []
            # TODO - determine better method of finding offset
            start = 0x72b0c  # will change for other versions of winlogon
            current = start
            while True:
                value = ps_ad.zread(base + current, 4)
                value = struct.unpack("<L", value)[0]
                if value > 0 and value % 0x1000 == 0:
                    addrs.append(value)
                    current += 0x8
                else:
                    break
            return addrs
        else:
            return []

    def get_ole32_allocations(self, task, ps_ad, start):
        """Get unverifiable allocations created by ol32.dll"""
        # TODO - find better method of locating
        value = ps_ad.zread(start + 0x148A2C, 4)
        value = struct.unpack("<L", value)[0]
        if value > 0:
            return value, "ole32.dll executable allocation"
        else:
            return -1, ""

    def get_ntdll_heap(self, task, ps_ad, start):
        """Get unverifiable heap created by ntdll.dll"""
        # TODO - find better method of locating
        value = ps_ad.zread(start + 0xD7514, 4)
        value = struct.unpack("<L", value)[0]
        if value > 0:
            return value, "ntdll.dll executable heap"
        else:
            return -1, ""

    def get_explorer_alloc(self, task, ps_ad, vads, names):
        """Get unverifiable allocation created by explorer.exe"""
        for start, end in vads:
            # determine based on data structure within allocation
            if (end - start + 1) == 0x1000 and start not in names:
                value = ps_ad.zread(start + 0x10, 4)
                value = struct.unpack("<L", value)[0]
                if value == start:
                    yield start, "explorer.exe executable allocation"


    def get_special_allocs(self, task, ps_ad, names):
        """Get allocations that are partially verifiable but perform behaviour
           that prevents complete verification"""
        if str(task.ImageFileName) == "SearchIndexer." and "shell32.dll" in names.values():
            start = self.find_start(names, "shell32.dll")
            yield start, "shell32/fdproxy/pnidui/wpdshserviceobj dll combination"
        elif str(task.ImageFileName) == "wmpnetwk.exe" and "blackbox.dll" in names.values():
            start = self.find_start(names, "blackbox.dll")
            yield start, "blackbox.dll - Encrypted DRM Component"

    def get_unverifiable_allocs(self, task, ps_ad, vads, names):
        """Get all allocations that are unverifiable for this process"""
        if str(task.ImageFileName) == "SearchFilterHo" and "ntdll.dll" in names.values():
            start = self.find_start(names, "ntdll.dll")
            offset, desc = self.get_ntdll_heap(task, ps_ad, start)
            yield offset, desc
        if "ole32.dll" in names.values():
            start = self.find_start(names, "ole32.dll")
            offset, desc = self.get_ole32_allocations(task, ps_ad, start)
            yield offset, desc
        if str(task.ImageFileName) == "explorer.exe":
            for offset, desc in self.get_explorer_alloc(task, ps_ad, vads, names):
                yield offset, desc

    def find_start(self, names, target):
        """Locate start address of an allocation by name"""
        for start, name in names.iteritems():
            if name == target:
                return start
        return -1

    def test(self, task, desktop_heap_segments):
        """Test the executable allocations against the hash set"""
        # TODO - I have a version that looks for executable pages in all allocations
        #        rather than use allocation permissions. Need to port changes across
        #      - Clean up this function

        # get the executable memory allocations
        ps_ad, vads, names, unverifiable, special = self.ranges(task, desktop_heap_segments)
        # for each executable allocation
        pid = task.UniqueProcessId
        index = self.build_index()
        for [start, end] in vads:
            # track information about allocation
            is_verifiable = True
            is_present = False
            paged = 0
            matches = 0
            offset = 0x0
            data_pages = 0
            data_matches = 0
            exec_data = 0
            # get allocation name
            file_hashes = []
            if start in names:
                filename = names[start]
                if start in unverifiable:
                    # completely unverifiable
                    is_verifiable = False
                    # do not count duplicate allocations
                    if unverifiable[start] not in self.unverifiable_allocs or unverifiable[start] == 0:
                        # make sure each winlogon exe_rw alloc
                        # and each process-specific alloc is counted
                        self.unverifiable_allocs.append(unverifiable[start])
                elif start in special:
                    # able to be partially verified but still on the whole unverifiable
                    is_verifiable = False
                    # get hashes
                    file_hashes = self.hashes(index, filename)

                    # change name to description of contents
                    filename = special[start]
                    self.unverifiable_allocs.append(special[start])
                else:
                    # get hashes for allocation that can be verfied
                    try:
                        file_hashes = self.hashes(index, filename)
                    except KeyError:
                        pass
            else:
                # unknown allocation
                filename = ""
            if len(file_hashes) > 0:
                is_present = True
            hash_index = 0
            # hash each page in allocation and record results
            while start + offset < end:
                # collect allocation statistics
                is_data = False
                if not(ps_ad.is_valid_address(start + offset)):
                    #paged out
                    paged += 1
                    offset += 0x1000
                    continue
                if not(self.check_executable(ps_ad, start + offset)):
                    #not executable, data page
                    is_data = True
                    data_pages += 1
                # test each page against its hash
                data = ps_ad.zread(start + offset, 0x1000)
                while hash_index < len(file_hashes):
                    # locate hash information
                    hash = file_hashes[hash_index]
                    if offset / 0x1000 > hash[1]:
                        hash_index += 1
                        continue
                    elif hash[1] > offset / 0x1000:
                        # no match found
                        if not(is_data):
                            if hash[3] == 0:
                                exec_data += 1
                            else:
                                # dump unknown or unverifiable executable page
                                self.dump(data, pid, offset, filename)
                        break
                    # normalise out regions, hash and compare
                    new_data = self.zero(data, hash[4])
                    new_hash = hashlib.sha1(new_data).hexdigest()
                    if new_hash == hash[2]:
                        # track match information
                        if is_data:
                            data_matches += 1
                        else:
                            matches += 1
                        break
                    else:
                        hash_index += 1
                offset += 0x1000
            # output results
            available = offset / 0x1000 - paged - data_pages
            yield start, matches, available, exec_data, filename, is_verifiable, is_present

    def dump(self, data, pid, offset, filename):
        """Dump unknown or unverifiable pages to a file"""
        if filename == "":
            filename = "Unknown"
        filename = filename.replace("/", "-")
        f = open("{0}/{1}-{2:08x}-{3}-m.bin".format(self._config.DUMPDIR, pid, offset, filename), "w")
        f.write(data)
        f.close()

    def check_executable(self, ps_ad, vaddr):
        """Checks if the page which contains the virtual address is executable"""
        pdpe = ps_ad.get_pdpi(vaddr)
        pgd = ps_ad.get_pgd(vaddr, pdpe)
        pte = ps_ad.get_pte(vaddr, pgd)

        # Check NX bit
        if pte & 1 << 63 == 1 << 63:
            # not executable
            return False        
        else:
            # check for transition
            if not (pte & 1) and pte & 1 << 11 == 1 << 11 and pte & 1 << 10 == 0:
                # transition page, check pfn
                return self.check_pfn(self.kernel_space, self.pfn_addr, pte >> 12)
            else:
                # normal executable page
                return True

    def zero(self, data, pointers):
        """Zero out (normalise) the locations of the pointers"""
        new_data = ""
        last = 0
        for pointer in pointers:
            if 0 <= pointer <= 4092:
                # normal case
                new_data += data[last:pointer]
                new_data += "\x00\x00\x00\x00"
            elif pointer < 0:
                # overlapping zero from previous page
                new_data += "\x00" * (4 + pointer)
            elif pointer > 4092:
                # zero continues into next page
                new_data += data[last:pointer]
                new_data += "\x00" * (4096 - pointer)
            last = pointer + 4
        if last <= 4096:
            new_data += data[last:]
        return new_data

    def build_index(self):
        """Build index in memory of locations of files in hash set
           to speed retrieval"""
        f = open(self._config.HASHSET, "r")
        index = {}
        line = f.readline()
        name = line.split(",")[0]
        current_name = name
        start = 0
        position = 0
        while line != "":
            # parse line to determine filename
            name = line.split(",")[0]
            if name != current_name:
                position = f.tell()
                # -1 on size to strip trailing \n
                index[current_name] = [start, position - start - 1]
                start = position - len(line)
                current_name = name
            line = f.readline()
        return index

    def hashes(self, index, filename):
        """ Retrieve hashes for the given filename"""
        start, size = index[filename]
        f = open(self._config.HASHSET, "r")
        f.seek(start)
        hashes = f.read(size)
        f.close()
        hashes = hashes.split("\n")
        hashes = map(self.parse, hashes)
        return hashes

    def parse(self, line):
        """Parse each line of the hash information"""
        # remove the line separator
        hash = line.split(",")
        hash[1] = int(hash[1], 16)      # offset
        hash[3] = int(hash[3])          # permission
        hash[4] = hash[4].split(" ")    # locations to normalise
        if hash[4] == [""]:
            hash[4] = []
        else:
            # convert hash offsets to decimal
            hash[4] = [int(x, 16) for x in hash[4]]
        return hash

    def check_pfn(self, kernel_space, pfn_addr, pfn):
        """Check the protection flags in the pfn entry of the transition pte"""
        mmpfn = obj.Object("_MMPFN",
                          offset = pfn_addr + pfn * self.mmpfn_size,
                          vm = self.kernel_space)
        protection = mmpfn.OriginalPte.u.Trans.Protection
        if protection & 1 << 1 == 1 << 1:
            #executable
            return True
        else:
            return False


