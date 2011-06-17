from distutils.core import setup
from distutils.extension import Extension
from Cython.Distutils import build_ext
from subprocess import Popen, PIPE

def pkg_config(libname):
    proc = Popen(["pkg-config",
                  libname,
                  "--cflags",
                  "--libs"],
                 stdin = PIPE,
                 stdout = PIPE,
                 stderr = PIPE)
    output = proc.communicate()[0]
    flags = output.split()
    return {'libraries': [f[2:] for f in flags if f[:2] == "-l"],
            'include_dirs': [f[2:] for f in flags if f[:2] == "-I"],
            'library_dirs': [f[2:] for f in flags if f[:2] == "-L"]}
    

ext_modules = [
    Extension(
        "pygmi.gmimelib.gmime", 
        ["src/pygmi/gmimelib/gmime.pyx"],
        libraries = pkg_config('gmime-2.4')['libraries'],
        include_dirs = pkg_config('gmime-2.4')['include_dirs'] + ['src/pygmi/gmimelib'],
        library_dirs = pkg_config('gmime-2.4')['library_dirs']
        )
    ]

setup(
  name = 'pygmi',
  packages = ['pygmi', 'pygmi.gmimelib'],
  package_dir = {'':'src'},
  cmdclass = {'build_ext': build_ext},
  ext_modules = ext_modules,
)
