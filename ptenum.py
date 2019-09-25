#  DESCRIPTION
#
#    Copyright (c) 2019, Frank Block, ERNW Research GmbH <fblock@ernw.de>
#
#       All rights reserved.
#
#       Redistribution and use in source and binary forms, with or without modification,
#       are permitted provided that the following conditions are met:
#
#       * Redistributions of source code must retain the above copyright notice, this
#         list of conditions and the following disclaimer.
#       * Redistributions in binary form must reproduce the above copyright notice,
#         this list of conditions and the following disclaimer in the documentation
#         and/or other materials provided with the distribution.
#       * The names of the contributors may not be used to endorse or promote products
#         derived from this software without specific prior written permission.
#
#       THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
#       AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
#       IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
#       ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
#       LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
#       DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
#       SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
#       CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
#       OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#       OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

"""Description for the plugin

To include this plugin, place it (or a symlink) into the rekall/plugins/windows
folder and add an entry to the __init__.py file, similar to this:
    from rekall.plugins.windows import basic
"""

__author__ = "Frank Block <fblock@ernw.de>"

import struct
from rekall import plugin
from rekall import addrspace
from rekall_lib import utils
from rekall.plugins import core
from rekall.plugins.addrspaces import intel
from rekall.plugins.windows import common
from rekall.plugins.windows import pagefile


class PteEnumerator(core.DirectoryDumperMixin, common.WinProcessFilter):
    """Description
    """

    name = "ptenum"
    
    dump_dir_optional = True
    default_dump_dir = None
    PAGE_SIZE = 0x1000
    # The empty page test uses this a lot, so we keep it once
    ALL_ZERO_PAGE = b"\x00" * PAGE_SIZE
    # Those pages will probably not occur that much, and we don't want to keep
    # a gigabyte of zeroes in memory
    LARGE_PAGE_SIZE = 0x200000
    LARGE_ARM_PAGE_SIZE = LARGE_PAGE_SIZE * 2
    HUGE_PAGE_SIZE = 0x40000000


    table_header = [
        dict(name="divider", type="Divider"),
        dict(name="task", hidden=True),
        dict(name="pointer", width=12, style="address"),
        dict(name="value", width=26),
    ]
    
    __args = [
        dict(name='start', type='IntParser', default=0,
             help=("The lowest address to examine; default=0")),
        dict(name='end', type='IntParser', default=None,
             help=("Upper limit address to examine; default: highest usermode "
                   "address")),
        dict(name='ignore_mapped_files', type='Boolean', default=False,
             help=("Don't print executable pages belonging to mapped files."))
    ]


    def __init__(self, *args, **kwargs):
        super(PteEnumerator, self).__init__(*args, **kwargs)
        self._init_masks()
        self._init_enums()
        self.mmpfn_db = self.profile.get_constant_object("MmPfnDatabase")

        if self.session.profile.metadata("arch") == 'AMD64':
            self.get_exec_pages_method = self.get_executable_pages
            self.proto_pointer_identifier = 0xffffffff0000

        elif self.session.profile.metadata("arch") == 'I386':
            self.get_exec_pages_method = self.get_executable_pages_x86
            self.proto_pointer_identifier = 0xffffffff

        else:
            raise plugin.PluginError("Unsupported architecture")


    # derived from rekall-core/rekall/plugins/addrspaces/amd64.py
    def _get_available_PDPTEs(self, start=0, end=2**64):
        # Pages that hold PDEs and PTEs are 0x1000 bytes each.
        # Each PDE and PTE is eight bytes. Thus there are 0x1000 / 8 = 0x200
        # PDEs and PTEs we must test.
        for pml4e_index in range(0, 0x200):
            vaddr = pml4e_index << 39
            if vaddr > end:
                return

            next_vaddr = (pml4e_index + 1) << 39
            if start >= next_vaddr:
                continue

            pml4e_addr = ((self.dtb & 0xffffffffff000) |
                          ((vaddr & 0xff8000000000) >> 36))
            pml4e_value = self.task_as.read_pte(pml4e_addr)

            # TODO paged out paging structures have valid bit unset,
            # but if the pagefile is supplied, we still could read it.
            if not pml4e_value & self.task_as.valid_mask:
                continue

            tmp1 = vaddr
            for pdpte_index in range(0, 0x200):
                vaddr = tmp1 + (pdpte_index << 30)
                if vaddr > end:
                    return

                next_vaddr = tmp1 + ((pdpte_index + 1) << 30)
                if start >= next_vaddr:
                    continue

                # Bits 51:12 are from the PML4E
                # Bits 11:3 are bits 38:30 of the linear address
                pdpte_addr = ((pml4e_value & 0xffffffffff000) |
                              ((vaddr & 0x7FC0000000) >> 27))
                pdpte_value = self.task_as.read_pte(pdpte_addr)

                # TODO paged out paging structures have valid bit unset,
                # but if the pagefile is supplied, we still could read it.
                if not pdpte_value & self.task_as.valid_mask:
                    continue

                yield [vaddr, pdpte_value]


    # derived from rekall-core/rekall/plugins/addrspaces/amd64.py
    def _get_available_PDEs(self, vaddr, pdpte_value, start=0, end=2**64):
        # This reads the entire PDE table at once - On
        # windows where IO is extremely expensive, its
        # about 10 times more efficient than reading it
        # one value at the time - and this loop is HOT!

        pde_table_addr = self.task_as._get_pde_addr(pdpte_value, vaddr)
        if pde_table_addr is None:
            return

        data = self.task_as.base.read(pde_table_addr, 8 * 0x200)
        pde_table = struct.unpack("<" + "Q" * 0x200, data)

        tmp2 = vaddr
        for pde_index in range(0, 0x200):
            vaddr = tmp2 + (pde_index << 21)
            if vaddr > end:
                return

            next_vaddr = tmp2 + ((pde_index + 1) << 21)
            if start >= next_vaddr:
                continue

            pde_value = pde_table[pde_index]

            # TODO Paged out paging structures have valid bit unset,
            # but if the pagefile is supplied, we still could read it.
            # Currently, we skip PDE if it is not valid or not in transition.
            if not (pde_value & self.task_as.valid_mask or 
                    pde_value & self.proto_transition_mask ==
                    self.transition_mask):
                continue

            yield [vaddr, pde_table[pde_index]]


    # taken from rekall-core/rekall/plugins/windows/pagefile.py
    def _get_available_PTEs(self, pde_value, vaddr, start=0, end=2**64,
                            ignore_vad=False):
        """Scan the PTE table and yield address ranges which are valid."""
        
        # This reads the entire PTE table at once - On
        # windows where IO is extremely expensive, its
        # about 10 times more efficient than reading it
        # one value at the time - and this loop is HOT!
        pte_table_addr = (pde_value & 0xffffffffff000) | \
                         ((vaddr & 0x1ff000) >> 9)

        # Invalid PTEs.
        if pte_table_addr is None:
            return

        data = self.task_as.base.read(pte_table_addr, 8 * 0x200)
        pte_table = struct.unpack("<" + "Q" * 0x200, data)

        tmp = vaddr
        for i in range(0, len(pte_table)):
            pfn = i << 12
            pte_value = pte_table[i]

            vaddr = tmp | pfn
            if vaddr > end:
                return

            next_vaddr = tmp | ((i + 1) << 12)
            if start >= next_vaddr:
                continue

            # A PTE value of 0 means to consult the vad, but the vad shows no
            # mapping at this virtual address, so we can just skip this PTE in
            # the iteration.
            if self.vad and not ignore_vad:
                start, _, _ = self.vad.get_containing_range(vaddr)
                if start is None:
                    start = 0
                    continue

            yield [vaddr, pte_value]


    def get_executable_pages(self, start=0, end=2**64):
        """Enumerate all available ranges.

        Yields Run objects for all available ranges in the virtual address
        space.
        """

        for pdpte_vaddr, pdpte_value in self._get_available_PDPTEs(start, end):
            if pdpte_vaddr & self.task_as.valid_mask and \
                    pdpte_value & self.task_as.page_size_mask:
                # huge page (1 GB)
                if not pdpte_value & self.nx_mask:
                    yield addrspace.Run(
                        start=pdpte_vaddr,
                        end=pdpte_vaddr + self.HUGE_PAGE_SIZE,
                        file_offset=((pdpte_value & 0xfffffc0000000) |
                                     (pdpte_vaddr & 0x3fffffff)),
                        address_space=self.task_as.base,
                        data={'pte_value': pdpte_value, 'proto': False})
                continue
            
            for pde_vaddr, pde_value in self._get_available_PDEs(pdpte_vaddr, pdpte_value, start, end):
                if pde_value & self.task_as.valid_mask and \
                        pde_value & self.task_as.page_size_mask:
                    # large page
                    if not pde_value & self.nx_mask:
                        yield addrspace.Run(
                            start=pde_vaddr,
                            end=pde_vaddr + self.LARGE_PAGE_SIZE,
                            file_offset=(pde_value & 0xfffffffe00000) | (
                                pde_vaddr & 0x1fffff),
                            address_space=self.task_as.base,
                            data={'pte_value': pde_value, 'proto': False})
                    continue
                    
                for vaddr, pte_value in self._get_available_PTEs(pde_value, pde_vaddr, start, end):
                    run = self.is_page_executable(vaddr, pte_value)
                    if run:
                        yield run


    def _is_demand_zero_pte(self, pte_value):
        
        # We are not interested in DemandZero pages
        if pte_value == 0:
            return True

        # We are also not interested in Guard Pages or 
        # Demand Zero pages with a modified Protection.
        # These pages have only the _MMPTE_SOFTWARE.Protection
        # field set.
        if not (pte_value & self.soft_protection_mask_negated):
            return True
            
        return False


    # TODO Integrate changes in pagefile.py
    #      Waiting for https://github.com/google/rekall/pull/501
    def _get_subsection_mapped_address(self, subsection_pte, isAddress=True):
        """Map the subsection into the physical address space.

        is_address specifies whether subsection_pte is the address of the pte
        or its value (true means it is the address)

        Returns:
          The offset in the physical AS where this subsection PTE is mapped to.
        """
        if self.task_as.base_as_can_map_files:
            if isAddress:
                pte = self.session.profile._MMPTE(subsection_pte)
            else:
                pte = self.session.profile._MMPTE()
                pte.u.Long = subsection_pte

            subsection = pte.u.Subsect.Subsection
            subsection_base = subsection.SubsectionBase.v()

            filename = subsection.ControlArea.FilePointer.file_name_with_drive()
            if filename:
                # The offset within the file starts at the beginning sector of
                # the section object, plus one page for each PTE. A section
                # object has an array of PTEs - the first one is 0 pages from
                # the start of the section, and each other PTE is another page
                # into the file. So we calculate the total number of pages from
                # the array index of the subsection_pte_address that we were
                # given.
                file_offset = (
                    (subsection_pte -
                     subsection_base) * 0x1000 / pte.obj_size +
                    subsection.StartingSector * 512)

                return self.task_as.base.get_mapped_offset(filename, file_offset)


    def is_page_executable(self, vaddr, pte_value):
        """This function returns a Run object for pages that are executable.
        It will, however, skip pages that have not yet been accessed, even if
        they would be executable once accessed."""

        executable = False
        phys_addr = None

        if self._is_demand_zero_pte(pte_value):
            return None

        # active page
        if pte_value & self.valid_mask:
            if not pte_value & self.nx_mask:
                pfn = ((pte_value & self.hard_pfn_mask) >> self.hard_pfn_start)
                phys_addr = (pfn << self.hard_pfn_start | (vaddr & 0xfff))
                executable = True
            else:
                return None

        # proto-pointer
        elif pte_value & self.prototype_mask:
            proto_address = ((self.proto_protoaddress_mask & pte_value) >>
                             self.proto_protoaddress_start)
            if (proto_address == self.proto_pointer_identifier):
                protection_value = ((pte_value & self.soft_protection_mask)
                                    >> self.soft_protection_start)
                # We observed this state for mapped data files
                # with no COPY-ON-WRITE.
                # As it is unusual to have a data file mapped with
                # executable rights, we report these.       
                if protection_value in self._executable_choices:
                    # Gathering the physical address this way at this point
                    # is inefficient, as it traverses the page tables again,
                    # but since this state is reached very seldom, we use this
                    # lazy approach for now.
                    phys_addr = \
                        self.task_as._get_phys_addr_from_pte(
                            vaddr, pte_value)
                    executable = True

                else:
                    return None

            # in this case, we have to analyze the prototype PTE
            else:
                protection_value = ((pte_value & self.proto_protection_mask) >>
                                    self.proto_protection_start)
                if protection_value in self._executable_choices:
                    phys_addr = \
                        self.task_as._get_phys_addr_from_pte(vaddr, pte_value)
                    executable = True
                else:
                    proto_value = self.task_as.read(proto_address,8)
                    proto_value = struct.unpack('<Q', proto_value)[0]
                    return self.is_page_executable_proto(vaddr, proto_value)

        # in transition
        elif pte_value & self.transition_mask:
            if ((pte_value & self.soft_protection_mask) >> 
                    self.soft_protection_start) in \
                    self._executable_choices:
                pfn = ((pte_value & self.trans_pfn_mask) >>
                       self.trans_pfn_start)
                phys_addr = (pfn << self.trans_pfn_start | vaddr & 0xfff)
                executable = True
            else:
                return None

        # pagefile PTE
        elif pte_value & self.soft_pagefilehigh_mask:
            if ((pte_value & self.soft_protection_mask) >>
                    self.soft_protection_start) in \
                    self._executable_choices:

                pagefile_address = \
                    (((pte_value & self.soft_pagefilehigh_mask)
                      >> self.soft_pagefilehigh_start)
                     * 0x1000 + (vaddr & 0xFFF))
                pagefile_num = \
                    ((pte_value & self.soft_pagefilelow_mask)
                     >> self.soft_pagefilelow_start)
                # TODO Verify the phys_addr part. Rekall's pagefile support
                #      seems to be broken at the moment.
                #      If the pagefile support doesn't work, the actual content
                #      can't be read but the plugin will still report the page.
                phys_addr = \
                    self.task_as._get_pagefile_mapped_address(pagefile_num,
                                                              pagefile_address)
                executable = True
            else:
                return None

        if executable:
            return addrspace.Run(start=vaddr,
                end=vaddr + self.PAGE_SIZE,
                file_offset=phys_addr,
                address_space=self.task_as.base,
                data={'pte_value': pte_value, 'proto': False})

        # unknown state
        self.session.logging.warning(
            "Unknown PTE value: 0x{:x}".format(pte_value))
        return None


    def is_page_executable_proto(self, vaddr, pte_value):
        """This function returns a Run object for pages that are executable.
        It will, however, skip pages that have not yet been accessed, even if
        they would be executable once accessed."""

        executable = False
        phys_addr = None

        if self._is_demand_zero_pte(pte_value):
            return None

        # active page
        if pte_value & self.valid_mask:
            if not pte_value & self.nx_mask:
                pfn = ((pte_value & self.hard_pfn_mask) >> self.hard_pfn_start)
                phys_addr = (pfn << self.hard_pfn_start | (vaddr & 0xfff))
                executable = True
            else:
                return None

        # subsection
        elif pte_value & self.prototype_mask:
            if ((pte_value & self.soft_protection_mask) >>
                    self.soft_protection_start) in \
                    self._executable_choices:
                phys_addr = \
                    self._get_subsection_mapped_address(pte_value,
                                                        isAddress=False)

                executable = True
            else:
                return None

        # in transition
        elif pte_value & self.transition_mask:
            if ((pte_value & self.soft_protection_mask) >> 
                    self.soft_protection_start) in \
                    self._executable_choices:
                pfn = ((pte_value & self.trans_pfn_mask) >>
                       self.trans_pfn_start)
                phys_addr = (pfn << self.trans_pfn_start | vaddr & 0xfff)
                executable = True
            else:
                return None

        # pagefile PTE
        elif pte_value & self.soft_pagefilehigh_mask:
            if ((pte_value & self.soft_protection_mask) >>
                    self.soft_protection_start) in \
                    self._executable_choices:

                pagefile_address = \
                    (((pte_value & self.soft_pagefilehigh_mask)
                      >> self.soft_pagefilehigh_start)
                     * 0x1000 + (vaddr & 0xFFF))
                pagefile_num = \
                    ((pte_value & self.soft_pagefilelow_mask)
                     >> self.soft_pagefilelow_start)

                # TODO Verify the phys_addr part. Rekall's pagefile support
                #      seems to be broken at the moment.
                #      If the pagefile support doesn't work, the actual content
                #      can't be read but the plugin will still report the page.
                phys_addr = \
                    self.task_as._get_pagefile_mapped_address(pagefile_num,
                                                              pagefile_address)
                executable = True
            else:
                return None

        if executable:
            return addrspace.Run(start=vaddr,
                end=vaddr + self.PAGE_SIZE,
                file_offset=phys_addr,
                address_space=self.task_as.base,
                data={'pte_value': pte_value, 'proto': True})

        # unknown state
        self.session.logging.warning(
            "Unknown PTE value: 0x{:x}".format(pte_value))
        return None


    # taken from get_mappings in rekall-core/rekall/plugins/addrspaces/intel.py
    def get_available_PDEs_x86(self, start=0, end=2**64):
        """A generator of address, length tuple for all valid memory regions."""
        # Pages that hold PDEs and PTEs are 0x1000 bytes each.
        # Each PDE and PTE is eight bytes. Thus there are 0x1000 / 8 = 0x200
        # PDEs and PTEs we must test.
        for pdpte_index in range(0, 4):
            vaddr = pdpte_index << 30
            if vaddr > end:
                return

            next_vaddr = (pdpte_index + 1) << 30
            if start >= next_vaddr:
                continue

            # Bits 31:5 come from CR3
            # Bits 4:3 come from bits 31:30 of the original linear address
            pdpte_addr = (self.dtb & 0xffffffe0) | ((vaddr & 0xc0000000) >> 27)
            pdpte_value = self.task_as.read_pte(pdpte_addr)
            if not pdpte_value & self.task_as.valid_mask:
                continue

            tmp1 = vaddr
            for pde_index in range(0, 0x200):
                vaddr = tmp1 | (pde_index << 21)
                if vaddr > end:
                    return

                next_vaddr = tmp1 | ((pde_index + 1) << 21)
                if start >= next_vaddr:
                    continue

                # Bits 51:12 are from the PDPTE
                # Bits 11:3 are bits 29:21 of the linear address
                pde_addr = ((pdpte_value & 0xffffffffff000) |
                            ((vaddr & 0x3fe00000) >> 18))
                pde_value = self.task_as.read_pte(pde_addr)

                # TODO paged out paging structures have valid bit unset,
                # but if the pagefile is supplied, we still could read it.
                if not (pde_value & self.task_as.valid_mask or 
                        pde_value & self.proto_transition_mask ==
                        self.transition_mask):
                    continue

                yield [vaddr, pde_value]


    # taken from rekall-core/rekall/plugins/addrspaces/amd64.py
    def get_available_PTEs_x86(self, vaddr, pde_value, start=0, end=2**64):

        # This reads the entire PTE table at once - On
        # windows where IO is extremely expensive, its
        # about 10 times more efficient than reading it
        # one value at the time - and this loop is HOT!
        pte_table_addr = ((pde_value & 0xffffffffff000) |
                          ((vaddr & 0x1ff000) >> 9))

        data = self.task_as.base.read(pte_table_addr, 8 * 0x200)
        pte_table = struct.unpack("<" + "Q" * 0x200, data)

        tmp2 = vaddr
        for i, pte_value in enumerate(pte_table):
            vaddr = tmp2 | i << 12
            if vaddr > end:
                return

            next_vaddr = tmp2 | (i + 1) << 12
            if start >= next_vaddr:
                continue

            yield [vaddr, pte_value]


    def get_executable_pages_x86(self, start=0, end=2**64):

        for pde_vaddr, pde_value in self.get_available_PDEs_x86(start, end):
            if pde_value & self.task_as.valid_mask and \
                    pde_value & self.task_as.page_size_mask:
                if not pde_value & self.nx_mask:
                    yield addrspace.Run(
                        start=pde_vaddr,
                        end=pde_vaddr+0x200000,
                        file_offset=(pde_value & 0xfffffffe00000) | (
                            vaddr & 0x1fffff),
                        address_space=self.task_as.base)
                continue
            
            for vaddr, pte_value in self.get_available_PTEs_x86(pde_vaddr,
                                                                pde_value,
                                                                start, end):
                run = self.is_page_executable(vaddr, pte_value)
                if run:
                    yield run
                            
                            
    def _init_masks(self):
        pte = self.session.profile._MMPTE()
        self.prototype_mask = pte.u.Proto.Prototype.mask
        self.transition_mask = pte.u.Trans.Transition.mask
        self.valid_mask = pte.u.Hard.Valid.mask
        self.proto_protoaddress_mask = pte.u.Proto.ProtoAddress.mask
        self.proto_protoaddress_start = pte.u.Proto.ProtoAddress.start_bit
        self.soft_pagefilehigh_mask = pte.u.Soft.PageFileHigh.mask
        self.soft_pagefilehigh_start = pte.u.Soft.PageFileHigh.start_bit
        self.soft_pagefilelow_mask = pte.u.Soft.PageFileLow.mask
        self.soft_pagefilelow_start = pte.u.Soft.PageFileLow.start_bit
        self.soft_protection_start = 5
        self.soft_protection_mask = (0b11111 << self.soft_protection_start)
        self.soft_protection_mask_negated = \
            0xffffffffffffffff ^ self.soft_protection_mask
        self.proto_protection_start = 11
        self.proto_protection_mask = (0b11111 << self.proto_protection_start)
        self.proto_transition_mask = self.prototype_mask | self.transition_mask

        try:
            self.nx_mask = pte.u.Hard.NoExecute.mask
        except AttributeError:
            self.nx_mask = 1 << 63

        self.hard_pfn_mask = pte.u.Hard.PageFrameNumber.mask
        self.hard_pfn_start = pte.u.Hard.PageFrameNumber.start_bit
        self.trans_pfn_mask = pte.u.Trans.PageFrameNumber.mask
        self.trans_pfn_start = pte.u.Trans.PageFrameNumber.start_bit


    def _init_enums(self):
        enum = self.profile._MMPTE_SOFTWARE().Protection.choices
        self._executable_choices = \
            [int(k) for k, v in enum.items() if 'EXEC' in v.upper() or \
             'MM_PROTECT_ACCESS' in v.upper()]
        self._writable_choices = \
            [int(k) for k, v in enum.items() if 'WRITE' in v.upper()]


    def get_vad_for_address(self, address):
        vad_run = self.session.address_resolver._address_ranges.get_containing_range(address)
        if not vad_run[2]:
            self.session.logging.warning(
                "No VAD found for task {:d} and address 0x{:x}"
                .format(self.task.pid, address))
            return None
        return vad_run[2].vad


    def get_vad_filename(self, vad):
        filename = ""
        if vad.u.VadFlags.PrivateMemory == 0:
            filename = "Pagefile-backed section"
            try:
                file_obj = vad.ControlArea.FilePointer
                if file_obj:
                    filename = (file_obj.file_name_with_drive() or
                                "Pagefile-backed section")
            except AttributeError:
                pass

        return str(filename)


    def vad_contains_image_file(self, vad):
        try:
            sec_obj_poi = vad.ControlArea.FilePointer.SectionObjectPointer
            if sec_obj_poi.ImageSectionObject:
                return True
        except AttributeError:
            pass

        return False


    def vad_contains_mapped_file(self, vad):
        if isinstance(vad, int):
            return False

        return vad.u.VadFlags.VadType.v() == 2 or \
            self.get_vad_filename(vad) != ''


    def render_vad(self, renderer, vad, pages):
        sorted_pages = sorted(pages['x_pages'], key=lambda x: x.start)
        first_page = sorted_pages[0]
        first_printable_page = first_page
        memory_area_start = first_page.start if type(vad) == int else vad.Start

        i=1
        while not first_printable_page.file_offset and i < len(sorted_pages):
            first_printable_page = sorted_pages[i]
            i+=1

        p_bytes = sum([x.length for x in pages['x_pages']])
        renderer.section()
        renderer.format(
            "Process: {0} Pid: {1} Address: {2:#x}\n",
            self.task.ImageFileName,
            self.task.UniqueProcessId,
            memory_area_start)

        if type(vad) == int:
            renderer.format(
                "The page at {0} with a size of {1} bytes is executable but "
                "not related to any known VAD. This can, but does not have to "
                "be suspicious.\n",
                hex(first_printable_page.start),
                hex(first_printable_page.length))

            if not first_printable_page.file_offset:
                renderer.format(
                    "The page is not available from the memory dump (e.g. "
                    "because it has been paged out). So there is nothing to "
                    "dump/disassemble here.\n")
                renderer.format("\n")
                return

        else:
            renderer.format("Vad Tag: {0} Protection: {1}\n",
                            vad.Tag, vad.u.VadFlags.ProtectionEnum)
        
            renderer.format("Flags: {0}\n", vad.u.VadFlags)
            filename = ''
            if self.vad_contains_mapped_file(vad):
                filename = self.get_vad_filename(vad)
                renderer.format("Mapped File: {0}\n", filename)
    
            vadtype = "Private"
            if vad.u.VadFlags.PrivateMemory <= 0:
                if filename == "Pagefile-backed section":
                    vadtype = "Mapped"
                else:
                    sec_obj_poi = vad.ControlArea.FilePointer.SectionObjectPointer
                    if sec_obj_poi.ImageSectionObject:
                        vadtype = "Mapped Image File"
                    else:
                        vadtype = "Mapped Data File"
            renderer.format("The Vadtype is: {0}\n", vadtype)

            renderer.format(
                "{0} non empty page(s) with a total size of {1} bytes in this "
                "VAD were executable (and for mapped image files also "
                "modified).\n".format(len(pages['x_pages']), hex(p_bytes)))

            if not first_printable_page.file_offset:
                renderer.format(
                    "Seems like all executable pages from this VAD are not "
                    "available from the memory dump (e.g. because they have "
                    "been paged out). So there is nothing to dump/disassemble "
                    "here.\n") 
                renderer.format("\n")
                return
    
            skipped_bytes = int(first_page.start - vad.Start)
            if skipped_bytes:
                renderer.format(
                    "Skipping the first {0} bytes, as they are either not "
                    "modified (only applies for mapped image files), empty or "
                    "not executable.\n", hex(skipped_bytes))
    
            elif first_printable_page.start != first_page.start:
                renderer.format(
                    "We only start printing at {0} as the first {1} "
                    "bytes seem to be not available from the memory dump "
                    "(e.g. because they have been paged out). But the first "
                    "executable page is at {2}.\n", 
                    hex(first_printable_page.start),
                    hex(first_printable_page.start-first_page.start),
                    hex(first_page.start))

        renderer.format("\n")
        dumper = self.session.plugins.dump(
            offset=first_printable_page.start, rows=4)
        dumper.render(renderer, suppress_headers=True)
    
        renderer.format("\n")

        disassembler = self.session.plugins.dis(
            offset=first_printable_page.start, length=0x40)
        disassembler.render(renderer, suppress_headers=True)

        if self.dump_dir:
            filename = "{0}.{1:d}.{2:08x}-{3:08x}.dmp".format(
                self.task.ImageFileName, self.task.pid, vad.Start,
                vad.End)
    
            with renderer.open(directory=self.dump_dir,
                               filename=filename,
                               mode='wb') as fd:
                self.session.report_progress(
                    "Dumping %s" % filename)
    
                self.CopyToFile(self.task_as, vad.Start, vad.End, fd)
        renderer.format("\n")


    def is_page_empty(self, run):
        """
        Check if the given virtual address of a page belongs to valid
        physical page page and does not contain only zeros.

        @param page_offset: the virtual address of the page to analyze
        """

        if run.file_offset != None:
            if run.length == self.PAGE_SIZE:
                return run.address_space.read(run.file_offset, run.length) \
                    == self.ALL_ZERO_PAGE
            else:
                return run.address_space.read(run.file_offset, run.length) \
                    == b"\x00" * run.length

        return None


    def init_for_task(self, task=None):
        if not task:
            task = self.session.GetParameter("process_context")

        cc = self.session.plugins.cc()
        self.task = task
        self.task_as = task.get_process_address_space()
        cc.SwitchProcessContext(task)
        if not self.task_as or \
                self.task_as == self.session.kernel_address_space:
            return False

        self.vad = None
        self.dtb = task.dtb
        self.session.address_resolver._EnsureInitialized()
        return True
      

    def render(self, renderer):
        # used for pages not belonging to any vad
        no_vad_counter = 0
        for task in self.filter_processes():

            if not self.init_for_task(task):
                continue

            result = {}
            end = self.plugin_args.end or \
                  self.session.GetParameter("highest_usermode_address")

            for run in self.get_exec_pages_method(start=self.plugin_args.start,
                                                  end=end):
                self.session.report_progress(
                    "Inspecting Pid %d: 0x%08X", task.pid, run.start)
                vad = self.get_vad_for_address(run.start)
                if not vad:
                    # Each page not belonging to a vad is printed separately.
                    # We are using the no_vad_counter as an index for result.
                    no_vad_counter += 1
                    vad = no_vad_counter

                if vad not in result:
                    result[vad] = {'x_pages': [run]}
                else:
                    result[vad]['x_pages'].append(run)

            for vad, pages in result.items():
                if self.plugin_args.ignore_mapped_files and \
                        self.vad_contains_mapped_file(vad):
                    continue

                vad_contains_imagefile = None
                vad_should_be_printed = False
                drop_these_pages = []
                for run in pages['x_pages']:
                    proto = run.data['proto']
                    if not proto and run.file_offset:
                        pfn = run.file_offset >> 12
                        proto = self.mmpfn_db[pfn].u4.PrototypePte
                    
                    if proto and vad_contains_imagefile == None:
                        vad_contains_imagefile = \
                            self.vad_contains_image_file(vad)

                    # We skip unmodified pages for mapped image files, but
                    # still report unmodified executable pages for mapped data
                    # files as this is something suspicious to look for.
                    if proto and vad_contains_imagefile:
                        drop_these_pages.append(run)
                        continue

                    if self.is_page_empty(run):
                        drop_these_pages.append(run)
                        continue

                    vad_should_be_printed = True

                pages['x_pages'] = [x for x in pages['x_pages'] if x not in
                                    drop_these_pages]
                if not vad_should_be_printed or not pages['x_pages']:
                    continue

                self.render_vad(renderer, vad, pages)

