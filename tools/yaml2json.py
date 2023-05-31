import click
import yaml, json, os
from functools import partial
import warnings

warnings.filterwarnings('ignore')

def toFile(filename, content: str):
    with open(filename, "w", encoding="utf-8") as f:
        f.write(content)


def loadyaml(filename):
    print("loading " + filename)
    f = open(filename, "rb")
    return yaml.load(f.read(), Loader=yaml.FullLoader)

@click.command()
@click.argument("path", nargs=-1, type=click.Path(exists=True))
@click.option('--outfile', '-f', help='output file')
def main(path, outfile):
    pocs = []
    if not outfile:
        outfile = "poc.json"

    print("save to " + outfile)
    outfunc = partial(toFile, outfile)
    
    for p in path:
        if os.path.isdir(p):
            for root, dirs, files in os.walk(p):
                for file in files:
                    file_path = os.path.join(root, file)
                    if file_path.endswith("yml") or file_path.endswith("yaml"):
                        pocs.append(loadyaml(file_path))
        else:
            pocs.append(loadyaml(p))

    print("load %d pocs"%len(pocs))
    outfunc(json.dumps(pocs))

if __name__ == '__main__':
    main()