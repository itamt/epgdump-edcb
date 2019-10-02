import sys
import glob
import ast
import argparse
import itertools
from pathlib import Path
import xml.etree.ElementTree as ET
import xml.dom.minidom
from xml.etree.ElementTree import ElementTree
from typing import List, Tuple, Dict, Optional, Iterable

from epgdump_py.parser import TransportStreamFile, parse_ts
from epgdump_py.xmltv import create_xml
from epgdump_py.customtype import BType
from epgdump_py.constant import ONID_BS, ONID_CS1, ONID_CS2

# region 設定
DEFAULT_OUT_NAME_FMT = 'epgdump_edcb_{key}.xml'
# endregion 設定


def create_argparser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="""example:
    epgdump_edcb.py -s SETTING_FILE
    epgdump_edcb.py [-f] -a -i INPUT_DIR -of OUTPUT_FILE
    epgdump_edcb.py [-f] -a -i INPUT_DIR -od OUTPUT_DIR [-k1 all]
    epgdump_edcb.py [-f] -i INPUT_DIR -od OUTPUT_DIR [-kb bs] [-kc1 cs1] [-kc2 cs2] [-kg gr]""",
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.print_usage = parser.print_help  # overwrite usage by full help
    parser.add_argument('-a', '--all', action='store_true',
                        help='merge all dat into one file')
    parser.add_argument('-f', '--format', action='store_true',
                        help='format xml')
    parser.add_argument('-i', '--input-dir', type=str,
                        help='specify EDCB EpgData directory', metavar='INPUT_DIR')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-of', '--output-file', type=str,
                       help='specify xml file', metavar='OUTPUT_FILE')
    group.add_argument('-od', '--output-dir', type=str,
                       help='specify xml output directory', metavar='OUTPUT_DIR')
    group.add_argument('-s', '--setting-file', type=argparse.FileType('r'),
                       help='load settings from file', metavar='SETTING_FILE')
    parser.add_argument('-d', '--debug', action='store_true',
                        help='print debug message')
    return parser


def pick_dat_id(dat_path: Path) -> Tuple[int, int]:
    """EDCBが生成するdatファイル名からoriginal_network_id(ONID), transport_stream_id(TSID)を返す

    """
    if not dat_path.name.endswith('_epg.dat'):
        raise ValueError('invalid dat file name')
    datfile_id = dat_path.stem.split('_')[0]
    onid = int(datfile_id[0:4], 16)
    tsid = int(datfile_id[4:8], 16)
    return onid, tsid


def write_xml(xml_str: str, filepath: Path, pretty_print: bool) -> None:
    """XMLをファイルに書き込む

    """
    if pretty_print:
        with filepath.open(mode='wb') as f:
            xml_bytes = xml.dom.minidom.parseString(xml_str.encode('utf-8')).toprettyxml(indent='  ', encoding='utf-8')
            f.write(xml_bytes)
    else:
        with filepath.open(mode='w', encoding='utf-8') as f:
            f.write(xml_str)


def merge_xml(xmls: Iterable[ElementTree]) -> str:
    """XMLを文字列検索でマージして文字列で返す

    オブジェクトのままマージするのが面倒だったため
    """
    content = '<?xml version="1.0" encoding="utf-8"?><tv>'
    ch = ''
    pg = ''
    for xml_et in xmls:
        x_str = ET.tostring(xml_et.getroot(), encoding='utf-8').decode('utf-8')
        ch_start = x_str.index('<ch')
        ch_end = x_str.index('<programme')
        pg_start = x_str.index('<programme')
        pg_end = x_str.index('</tv>')
        ch += x_str[ch_start:ch_end]
        pg += x_str[pg_start:pg_end]
    content += ch + pg + '</tv>'
    return content


def main():
    argparser = create_argparser()
    args = argparser.parse_args()

    if args.setting_file:
        print(f"loading settings from {args.setting_file.name}")
        try:
            settings = ast.literal_eval(args.setting_file.read())
            epg_dir = Path(settings['EPG_DIR'])
            out_dir = Path(settings['OUT_DIR'])
            out_name_fmt = settings['OUT_NAME_FMT']
            out_file = None
            pretty_print: bool = settings['PRETTY_PRINT']
            merge_all: bool = settings['MERGE_ALL']
        except Exception:
            print(f"failed to load setting file. something is invalid.", file=sys.stderr)
            sys.exit(1)
    else:
        try:
            epg_dir = Path(args.input_dir.name)
            out_dir = Path(args.output_dir.name) if args.output_dir else None
            out_name_fmt = DEFAULT_OUT_NAME_FMT
            out_file: Optional[Path] = Path(args.output_file.name) if args.output_file else None
            pretty_print = bool(args.format)
            merge_all = bool(args.all)
        except Exception:
            print(f"some parameters are invalid.", file=sys.stderr)
            sys.exit(1)

    print('Prameters:',
          f"  mode: {'merge_all' if merge_all else 'merge_group'}",
          f"  format: {str(pretty_print).lower()}",
          f"  input: {epg_dir}",
          sep='\n')

    def get_outpath(key: str) -> Path:
        if merge_all and out_file:
            return out_file
        return out_dir / out_name_fmt.format(key=key)

    dat_paths: List[Path] = [Path(x) for x in glob.glob(f"{epg_dir}/*_epg.dat")]

    xmls_map: Dict[str, List[ElementTree]] = {
        'gr': [],
        'bs': [],
        'cs1': [],
        'cs2': [],
    }
    for dat in dat_paths:
        onid, tsid = pick_dat_id(dat)

        if onid == ONID_BS:
            b_type = BType.bs.value
            channel_id = None
            key = 'bs'
        elif onid == ONID_CS1:
            b_type = BType.cs.value
            channel_id = None
            key = 'cs1'
        elif onid == ONID_CS2:
            b_type = BType.cs.value
            channel_id = None
            key = 'cs2'
        else:
            b_type = BType.digital.value
            channel_id = '0'  # dummy
            key = 'gr'

        # BS, CSは1つのXMLで足りる
        if b_type in [BType.bs.value, BType.cs.value]:
            if xmls_map[key]:
                if args.debug:
                    print(f"skip dat: {dat.name}")
                continue

        print(f"parsing dat: {dat.name}")
        with TransportStreamFile(str(dat), 'rb') as tsfile:
            service, events = parse_ts(b_type, tsfile, debug=False)
        xml_et = create_xml(b_type, channel_id, service, events)
        xmls_map[key].append(xml_et)

    print(f"merging xml...")
    if merge_all:
        # 1ファイルにまとめる
        xmls = itertools.chain(*xmls_map.values())  # flatten List[list]
        merged_xml: str = merge_xml(xmls)

        outpath = get_outpath(key='all')
        write_xml(merged_xml, outpath, pretty_print)
        print(f"output: {outpath}")
    else:
        # 放送タイプごとに出力する
        for key, xmls in xmls_map.items():
            merged_xml: str = merge_xml(xmls)

            outpath = get_outpath(key=key)
            write_xml(merged_xml, outpath, pretty_print)
            print(f"output: {outpath}")


if __name__ == '__main__':
    main()
