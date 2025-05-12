import os
import click

monitored_octal_permissions = [
    '777',
    '666',
    '755',
    '775',
    '707',
    '757',
    '767'
]

@click.command()
@click.argument('directory')
def scan_directory(directory):
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            octal_permissions = oct(os.stat(file_path).st_mode)[-3:]
            risky_permissions(octal_permissions, file_path)

def risky_permissions(octal_permissions, path):
    if octal_permissions in monitored_octal_permissions:
        print(f'WARNING: File has excessive permissions! {octal_permissions}:{path}')

if __name__ == '__main__':
    scan_directory()
