"""Compile the production graphical launch contract for native device fixtures."""
import hashlib
from pathlib import Path
import subprocess
import shutil


def compile_recipe(classes):
    repo = Path(__file__).resolve().parents[2]
    names = ('LinuxGraphicalEnvironment', 'GuestGraphicalConnection', 'GuestLaunchPlan',
             'GuestEnvironment', 'GuestNetworkProfile', 'GraphicalProtocol', 'ShellCommandLine',
             'LinuxAudioEnvironment', 'GamepadWire')
    sources = [Path(__file__).with_name('GraphicalRecipe.java'),
               *(repo / 'app/src/main/java/io/github/mekhontsev/magicdesk' / (name + '.java')
                 for name in names)]
    classes.mkdir(parents=True, exist_ok=True)
    session = repo / 'native/magicdesk_guest_session.sh'
    shutil.copyfile(session, classes / session.name)
    # EVENT_WAIT: compiler exit; expiry fails preparation before client launch.
    subprocess.run(['javac', '-d', str(classes), *map(str, sources)], check=True, timeout=30)
    return {str(path.relative_to(repo)): hashlib.sha256(path.read_bytes()).hexdigest() for path in [*sources, session]}
