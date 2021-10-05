#!/usr/bin/env python3.6
#
# YANG Revision Tree
# (C) 2021 Cisco Systems, Jan Lindblad <jlindbla@cisco.com>

import os, sys, getopt, pathlib, subprocess, hashlib, csv, collections

class ParseError(Exception):
  def __init__(self, msg):
    self.msg = msg

  @property
  def message(self):
    return self.msg

class Module:
  """
  The Module class contains meta information about one YANG Module.
  """
  csv_fieldnames = ['modulename', 'modulerevision',
      'release', 'checksum', 'namespace', 'prefix',
      'kind', 'filename']

  @staticmethod
  def _strip_version(filename):
    if not '@' in filename:
      return filename
    return filename.split('@')[0]

  def __repr__(self):
    return f"<Module: {self.modulename}/{self.modulerevision} from {self.filename}>"

  def __init__(self, filepath_or_csvrow, modulepath=[], release = '', debug=False):
    if isinstance(filepath_or_csvrow, collections.OrderedDict):
      self._populate(filepath_or_csvrow)
    else:
      self._scan(filepath_or_csvrow, modulepath, release, debug)

  def _populate(self, csvrow):
    self.modinfo = dict(csvrow)

  def _scan(self, filepath, modulepath, release, debug): 
    if debug:
      print(f"Scanning {filepath.name}")
    result = subprocess.run(
      ["yanger", "-f", "sn"] + 
      [f(e) for e in modulepath for f in (lambda z:"-p",lambda z:e)] + 
      [filepath],
      stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, universal_newlines=True)

    self.modinfo = {
      'checksum': hashlib.md5(open(filepath,'rb').read()).hexdigest(),
      'release': release
    }
    for (lineno, line) in enumerate(result.stdout.split('\n'),1):
      if line == '}':
        break # The module section is done when we find an unindented end-brace
      # Data format:
      # %% module: tailf-ncs
      # #module{
      #   name = 'tailf-ncs'
      #   yang_version = '1.1'
      #   modulename = 'tailf-ncs'
      #   namespace = 'http://tail-f.com/ns/ncs'
      #   prefix = ncs
      #   modulerevision = <<"2021-02-09">>
      #   filename = "tailf-ncs.yang"
      # ...
      # }
      # ...
      piece = line.split(" = ")
      if len(piece) != 2:
        continue
      kw = piece[0].strip()
      if piece[1].startswith("'") or piece[1].startswith('"'):
        val = piece[1][1:-1] # Remove 'single' or "double" quotes first and last
      elif piece[1].startswith('<<"'):
        val = piece[1][3:-3] # Remove <<"binary-decoration">> first and last
      else:
        val = piece[1]
      if kw == 'modulename':
        # Check that it matches the filename
        expected_modname = Module._strip_version(filepath.name)
        if not expected_modname.startswith(val) and val[len(expected_modname):] in [".yang", ".yin"]:
          error_file_line(filepath, lineno, f"Module name '{val}' does not match the expected module name '{expected_modname}'")
      elif kw == 'yang_version':
        # FIXME: check that ancestors did not have greater rev
        if val not in ["1", "1.1"]:
          error_file_line(filepath, lineno, f"Unexpected YANG version '{val}'")
      elif kw == 'filename':
        # FIXME: compare these somehow
        if not val == filepath:
          pass#FIXMEerror_file_line(filepath, lineno, f"Scanned filename has an unexpected value '{val}' != '{filepath}'")
      # Ok, we have a modinfo, store it
      elif kw in ['namespace', 'prefix', 'modulerevision', 'kind']:
        pass
      else:
        continue
      self.modinfo[kw] = val
    if len(self.modinfo) < 5:
      raise(ParseError(result.stderr))

  @property
  def modulename(self):
    try:
      return self.modinfo['modulename']
    except:
      print(f"No modulename for {self.modinfo}")
      return "foo"

  @property
  def modulerevision(self):
    if self.modinfo['modulerevision'] == 'undefined':
      return self.checksum
    return self.modinfo['modulerevision']
  @property
  def release(self):
    return self.modinfo['release']
  @property
  def checksum(self):
    return self.modinfo['checksum']
  @property
  def namespace(self):
    return self.modinfo['namespace']
  @property
  def prefix(self):
    return self.modinfo['prefix']
  @property
  def kind(self):
    return self.modinfo['kind']
  @property
  def filename(self):
    return self.modinfo['filename']

  def get_row(self):
    return [self.modinfo.get(fieldname,'') for fieldname in Module.csv_fieldnames]

class Library:
  """
  The Library class represents a collection of releases, 
  where each release consists of a set of Modules.
  """

  NEW_MODULE = 0
  NEW_REVISION = 1
  KNOWN_REVISION = 2
  ERROR_BASE = 3
  COLL_PREFIX = 4
  COLL_NAMESPACE = 5
  DIFF_PREFIX = 6
  DIFF_NAMESPACE = 7
  DIFF_CHECKSUM = 8

  ANY_REVISION = None

  db_prefix = "REVINFO-"
  db_suffix = ".csv"

  def __init__(self, library_dir=None, debug=False):
    self.mods = {}
    self.new_results = {}
    self.namespaces = {}
    self.prefixes = {}
    self.logs = []
    self.library_dir = library_dir
    self.modulepath = []
    self.debug = debug

  def is_release_scanned(self, release_name):
    """
    Returns True if a REVINFO file already exists for the current
    """
    out_libpath = self.get_output_libpath(release_name)
    if out_libpath and out_libpath.exists():
      return True
    return False

  def get_module(self, mod_name, mod_rev):
    if mod_rev == Library.ANY_REVISION:
      return self.mods[mod_name][list(self.mods[mod_name].keys())[0]]
    return self.mods[mod_name][mod_rev]

  def get_module_names(self):
    return self.mods.keys()

  def get_module_revisions(self, mod_name):
    mod_revs = self.mods.get(mod_name)
    if not mod_revs:
      return []
    return mod_revs.keys()

  def load(self):
    if not self.library_dir:
      return

    dbfiles = list(pathlib.Path(self.library_dir).glob(Library.db_prefix + "*" + Library.db_suffix))
    if self.debug: print(f"DBG: Found {len(dbfiles)} dbfiles to consult")
    for dbfile in dbfiles:
      print(f"Loading database file {dbfile}")
      self.load_release(dbfile)

  def load_release(self, dbfile):
    if self.debug: print(f"DBG: Reading release info {dbfile}")
    with open(dbfile) as csvfile:
      revinfo_reader = csv.DictReader(csvfile)
      self.add_modules([Module(row) for row in revinfo_reader])

  def add_modules(self, mods, debug=False):
    for mod in mods:
      if mod.modulename not in self.get_module_names():
        # New module
        if debug: print(f"New module {mod}")
        self.mods[mod.modulename] = {mod.modulerevision:mod}
        if self.namespaces.get(mod.namespace) and mod.kind != 'submodule' and not mod.modulename.endswith("-ann"):
          self.log_error(Library.COLL_NAMESPACE, [self.namespaces.get(mod.namespace), mod])
          continue
        self.namespaces[mod.namespace] = mod
        if self.prefixes.get(mod.prefix) and not mod.modulename.endswith("-ann"):
          self.log_error(Library.COLL_PREFIX, [self.prefixes.get(mod.prefix), mod])
          continue
        self.prefixes[mod.prefix] = mod
        self.log_added(Library.NEW_MODULE, [mod])
      elif mod.modulerevision not in self.get_module_revisions(mod.modulename):
        # Existing module, new revision
        if debug: print(f"New revision of module {mod}")
        # Check that namespace and prefix are the same
        lib_mod = self.get_module(mod.modulename,Library.ANY_REVISION)
        self.mods[mod.modulename][mod.modulerevision] = mod
        if (lib_mod.namespace != mod.namespace and 
            mod.namespace != 'undefined' and 
            lib_mod.namespace != 'undefined'):
          #print(f"XXX '{mod.namespace}'")
          self.log_error(Library.DIFF_NAMESPACE, [lib_mod, mod])
          continue
        #self.namespaces[mod.namespace] += [mod]
        if lib_mod.prefix != mod.prefix:
          self.log_error(Library.DIFF_PREFIX, [lib_mod, mod])
        #self.prefixes[mod.prefix] += [mod]
      else:
        # Existing module, existing revision
        if debug: print(f"Existing revision of module {mod}")
        if self.get_module(mod.modulename,mod.modulerevision).checksum != mod.checksum:
          self.log_error(Library.DIFF_CHECKSUM, [self.get_module(mod.modulename, mod.modulerevision), mod])
        # Check that it's the same module
    print(f"    {len(mods)} module revisions added. Now {len(self.mods)} modules in {sum([len(rev) for rev in self.mods.values()])} revisions in library")
    return self

  def log_error(self, issue_code, mods):
    self.logs += [(issue_code, mods)]

  def log_added(self, success_code, mods):
    self.logs += [(success_code, mods)]

  def print_log(self, release_name):
    if release_name:
      print(f"Focusing on release {release_name}")
    else:
      print(f"Showing results for all releases")
    for (code, mods) in self.logs:
      if release_name:
        if not release_name in [mod.release for mod in mods]:
          # Error not relevant for named release
          continue
      if code == Library.NEW_MODULE:
        #print(f"New module  {mods[0].modulename}")
        pass
      elif code == Library.NEW_REVISION:
        print(f"New rev     {mods[0].modulename}/{mods[0].modulerevision}")
      elif code == Library.KNOWN_REVISION:
        print(f"=           {mods[0].modulename}/{mods[0].modulerevision}")
      elif code == Library.COLL_PREFIX:
        print(f"ERROR {code} ==>  Prefix collision between")
        for mod in mods:
          print(f"             {mod.modulename}/{mod.modulerevision} {mod.prefix} from {mod.release} {mod.filename}")
      elif code == Library.COLL_NAMESPACE:
        print(f"ERROR {code} ==>  Namespace collision between")
        for mod in mods:
          print(f"             {mod.modulename}/{mod.modulerevision} {mod.namespace} from {mod.release} {mod.filename}")
      elif code == Library.DIFF_PREFIX:
        print(f"ERROR {code} ==>  Modules with thge same name but different prefixes")
        for mod in mods:
          print(f"             {mod.modulename}/{mod.modulerevision} {mod.prefix} from {mod.release} {mod.filename}")
      elif code == Library.DIFF_NAMESPACE:
        print(f"ERROR {code} ==>  Modules with the same name but different namespaces")
        for mod in mods:
          print(f"             {mod.modulename}/{mod.modulerevision} {mod.namespace} from {mod.release} {mod.filename}")
      elif code == Library.DIFF_CHECKSUM:
        print(f"ERROR {code} ==>  Modules with the same name and revision but different checksums")
        for mod in mods:
          print(f"             {mod.modulename}/{mod.modulerevision} {mod.checksum} from {mod.release} {mod.filename}")
      else:
        print(f"ERROR {code} ==>  Generic error with")
        for mod in mods:
          print(f"             {mod.modulename}/{mod.modulerevision} from {mod.release} {mod.filename}")

  def get_module_revisions(self, mod_name):
    return self.mods.get(mod_name)

  def get_output_libpath(self, release_name):
    if self.library_dir:
      return pathlib.Path(self.library_dir, Library.db_prefix + release_name + Library.db_suffix)

  def write_out_new_results(self, release_name):
    outfile = self.get_output_libpath(release_name)
    if not outfile:
      print(f"No release name given, scan result not saved")
      return
    if outfile.exists():
      print(f"Output file '{outfile.name} already exists")
      return
    rows = 0
    with open(outfile, 'w', newline='') as csvfile:
      revinfo_writer = csv.writer(csvfile, quoting=csv.QUOTE_MINIMAL)
      revinfo_writer.writerow(Module.csv_fieldnames)
      for mod in self.new_results.values():
        revinfo_writer.writerow(mod.get_row())
        rows += 1
    print(f"Wrote module info for {rows} modules to {outfile}")
    if not rows:
      outfile.unlink()
      print(f"Empty scan result, {outfile} not written")

  def scan_release(self, release_name, files_to_scan, debug=True):
    module_info_dict = {}
    for filename in files_to_scan:
      filepath = pathlib.Path(filename)
      if filepath.is_dir():
        self.modulepath += [filepath]
        filepaths = filepath.glob('**/*.yang')
      else:
        filepaths = [filepath] 

      for current_filepath in filepaths:
        try:
          module_info_dict[current_filepath.name] = Module(
            current_filepath, self.modulepath, release=release_name, debug=debug)
        except ParseError as pe:
          warning(f"Skipping {current_filepath.name},\n{pe.msg}")
    self.new_results = {**self.new_results, **module_info_dict}
    return self.add_modules(module_info_dict.values())

  def show_scan_results(self):
    print("===== Scan results =====")
    for mod in self.mods:
      print(mod)

# Top level helper functions

def error(msg):
  print(f"### Error: {msg}")
  sys.exit(9)

def warning(msg):
  print(f"### Warning: {msg}")

def error_file_line(filename, line, msg):
  error(f"{filename}:{line}: {msg}")

def usage():
  print(f'''{sys.argv[0]}
    [-l | --library <directory with saved module info>]
    [-r | --release <name of the release to store new modules/revisions as coming from>] 
    [-p | --print   
    <modules-to-scan>
  Scans YANG modules for duplicate prefixes and revision dates.
  Uses Yanger, a YANG compiler you need to install.''')

def main():
  debug = False
  release_name = None
  library_dir = None
  print_scan = False
  try:
    opts, args = getopt.gnu_getopt(sys.argv[1:],"hdr:l:p",
      ["help", "debug", "library=", "release=", "release-name=", "print"])
  except getopt.GetoptError:
    usage()
    sys.exit(2)
  for opt, arg in opts:
    if opt in ('-h', '--help'):
      usage()
      sys.exit()
    elif opt in ("-l", "--library"):
      library_dir = arg
    elif opt in ("-p", "--print"):
      print_scan = True
    elif opt in ("-r", "--release", "--release-name"):
      release_name = arg
    elif opt in ("-d", "--debug"):
      debug = True
    else:
      print('Unknown option "%s", exiting.'%opt)
      sys.exit(2)

  files_to_scan = args

  if library_dir and not pathlib.Path(library_dir).is_dir():
    pathlib.Path(library_dir).mkdir(parents=False)

  if not library_dir:
    print(f'No library directory specified')
    return

  print(f'===== Reading library =====')
  load_lib = Library(library_dir=library_dir, debug=debug)
  load_lib.load()

  if debug: print(f'DBG: Files to scan: {files_to_scan}')
  if release_name:
    print(f'===== Scanning =====')
    if not load_lib.is_release_scanned(release_name):
      print(f'Scanning {len(files_to_scan)} locations:')
      load_lib.scan_release(release_name, files_to_scan, debug=debug)
      print(f'Writing database file for {release_name}:')
      load_lib.write_out_new_results(release_name)
      if print_scan:
        if debug: print(f'DBG: Showing scan results:')
        load_lib.show_scan_results()#scan_lib.show_scan_results()
    else:
      print(f'Release {release_name} already scanned, skipping scan')
  if debug: print(f'DBG: Load: {files_to_scan}')
  print(f'===== Scan result =====')
  load_lib.print_log(release_name)

if __name__ == '__main__':
  main()
