import sys
import os
import glob
import ast
import argparse
import traceback
from pathlib import Path
import xml.etree.ElementTree as ET
import xml.dom.minidom
from xml.etree.ElementTree import ElementTree
from dataclasses import dataclass
from logging import getLogger, StreamHandler
from typing import List, Tuple, Dict, Optional, Union

from tqdm import tqdm

from epgdump_py.parser import TransportStreamFile, parse_ts
from epgdump_py.xmltv import create_xml
from epgdump_py.customtype import BType
from epgdump_py.constant import ONID_BS, ONID_CS1, ONID_CS2

# region 設定
DEFAULT_OUT_NAME_FMT = 'epgdump_edcb_{key}.xml'
LINE_ENDING = '\n'  # TODO: \r\n にすると2回改行される
# endregion 設定

logger = getLogger(__name__)


@dataclass
class DatFile:
    path: Path
    size: int
    type: str
    key: str
    channel_id: Optional[str]


class TvXmlBuilder:
    _ch: str
    _pg: str
    _pretty_print: bool
    count: int

    def __init__(self, pretty_print: bool = False):
        self._ch = ''
        self._pg = ''
        self._pretty_print = pretty_print
        self.count = 0

    def add(self, xml_et: ElementTree) -> None:
        """XMLを文字列検索でマージして文字列で返す

        オブジェクトのままマージするのが面倒なのとマージしたXMLをオブジェクトにするとメモリを食うので
        """

        x_str = ET.tostring(xml_et.getroot(), encoding='utf-8').decode('utf-8')
        if self._pretty_print:
            x_str = format_xml(x_str, ret_type=str, newl=LINE_ENDING)
        ch_start = x_str.index('<channel')
        ch_end = x_str.index('<programme')
        pg_start = x_str.index('<programme')
        pg_end = x_str.index('</tv>')
        self._ch += x_str[ch_start:ch_end]
        self._pg += x_str[pg_start:pg_end]
        self.count += 1

    @property
    def content(self) -> str:
        if self._pretty_print:
            return '<?xml version="1.0" encoding="utf-8"?><tv>' \
                   + LINE_ENDING + self._ch \
                   + LINE_ENDING + self._pg \
                   + LINE_ENDING + '</tv>'
        else:
            return '<?xml version="1.0" encoding="utf-8"?><tv>' + self._ch + self._pg + '</tv>'


def create_argparser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="""example:
    epgdump_edcb.py -s SETTING_FILE
    epgdump_edcb.py [-f] -a -i INPUT_DIR -of OUTPUT_FILE
    epgdump_edcb.py [-f] -a -i INPUT_DIR -od OUTPUT_DIR
    epgdump_edcb.py [-f] -i INPUT_DIR -od OUTPUT_DIR""",
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


def format_xml(xml_str: str, ret_type: type = bytes, newl: str = '\n') -> Union[bytes, str]:
    xml_bytes: bytes = xml.dom.minidom.parseString(xml_str.encode('utf-8')).toprettyxml(
        indent='  ', encoding='utf-8', newl=newl)
    if ret_type is bytes:
        return xml_bytes
    else:
        return xml_bytes.decode('utf-8')


def main():
    argparser = create_argparser()
    args = argparser.parse_args()

    if args.debug:
        logger.setLevel('DEBUG')

    if args.setting_file:
        logger.info(f"load settings from {args.setting_file.name}")
        try:
            settings = ast.literal_eval(args.setting_file.read())
            epg_dir = Path(settings['EPG_DIR'])
            out_dir = Path(settings['OUT_DIR'])
            out_name_fmt = settings['OUT_NAME_FMT']
            out_file = None
            pretty_print = bool(settings['PRETTY_PRINT'])
            merge_all = bool(settings['MERGE_ALL'])
        except Exception:
            logger.error(f"Failed to load setting file. {traceback.format_exc(chain=False)}")
            sys.exit(1)
    else:
        try:
            epg_dir = Path(args.input_dir)
            out_dir = Path(args.output_dir) if args.output_dir else None
            out_name_fmt = DEFAULT_OUT_NAME_FMT
            out_file: Optional[Path] = Path(args.output_file) if args.output_file else None
            pretty_print = bool(args.format)
            merge_all = bool(args.all)
        except Exception:
            logger.error(f"Some parameters are invalid. {traceback.format_exc(chain=False)}")
            sys.exit(1)

    logger.info('Prameters:\n'
                f"  mode: {'merge_all' if merge_all else 'merge_group'}\n"
                f"  format: {str(pretty_print).lower()}\n"
                f"  input: {epg_dir}\n"
                f"  output: {out_file or out_dir}")

    has_err = False
    if not epg_dir.exists():
        logger.error(f"input directory not exists: {epg_dir}")
        has_err = True
    if (out_file and not out_file.parent.exists()) or (out_file is None and not out_dir.exists()):
        logger.error(f"output directory not exists")
        has_err = True
    if has_err:
        sys.exit(1)

    def get_outpath(key: str) -> Path:
        if merge_all and out_file:
            return out_file
        return out_dir / out_name_fmt.format(key=key)

    dat_paths: List[Path] = [Path(x) for x in glob.glob(f"{epg_dir}/*_epg.dat")]

    if len(dat_paths) == 0:
        logger.error('*_epg.dat not found')
        sys.exit(1)

    # datファイル取捨
    target_dats: List[DatFile] = []
    counts = {
        'bs': 0,
        'cs1': 0,
        'cs2': 0,
    }
    for dat_path in dat_paths:
        onid, tsid = pick_dat_id(dat_path)

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
            counts[key] += 1
            if counts[key] > 1:
                logger.debug(f"skip dat: {dat_path.name}")
                continue

        datfile = DatFile(path=dat_path, size=os.stat(str(dat_path)).st_size,
                          type=b_type, key=key, channel_id=channel_id)
        target_dats.append(datfile)

    merged_xml_map = {
        'all': TvXmlBuilder(pretty_print),
        'gr': TvXmlBuilder(pretty_print),
        'bs': TvXmlBuilder(pretty_print),
        'cs1': TvXmlBuilder(pretty_print),
        'cs2': TvXmlBuilder(pretty_print),
    }
    with tqdm(total=sum(x.size for x in target_dats)) as progress_bar:
        for dat in target_dats:
            # datからXML取得
            progress_bar.set_description(f"current: {dat.path.name}")
            with TransportStreamFile(str(dat.path), 'rb') as tsfile:
                service, events = parse_ts(dat.type, tsfile, debug=False)
            xml_et = create_xml(dat.type, dat.channel_id, service, events)

            # マージ
            key = 'all' if merge_all else dat.key
            merged_xml_map[key].add(xml_et)
            progress_bar.update(dat.size)

    # ファイル出力
    for key, merged_xml in merged_xml_map.items():
        if merged_xml.count > 0:
            outpath = get_outpath(key=key)
            with outpath.open(mode='w', encoding='utf-8') as f:
                f.write(merged_xml.content)
            print(f"output: {outpath}")


if __name__ == '__main__':
    handler = StreamHandler()
    handler.setLevel('DEBUG')
    logger.addHandler(handler)
    logger.setLevel('INFO')

    main()
