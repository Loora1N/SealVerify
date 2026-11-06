"""仅使用合成内容生成可重复构建的 OFD，供阅读验收与测试。"""

import argparse
from io import BytesIO
from pathlib import Path
import struct
from xml.sax.saxutils import escape
from zipfile import ZipFile, ZipInfo, ZIP_DEFLATED
import zlib

NS = 'xmlns:ofd="http://www.ofdspec.org/2016"'


def text(object_id, value, x=18, y=28, size=5, color="32 51 76"):
    return (f'<ofd:TextObject ID="{object_id}" Boundary="{x} {y} 174 14" '
            f'Font="1" Size="{size}"><ofd:FillColor Value="{color}"/>'
            f'<ofd:TextCode X="0" Y="{size}">{escape(value)}</ofd:TextCode></ofd:TextObject>')


def path(object_id, data, boundary, fill="23 92 99", stroke="false", extra=""):
    return (f'<ofd:PathObject ID="{object_id}" Boundary="{boundary}" '
            f'Fill="true" Stroke="{stroke}" {extra}><ofd:FillColor Value="{fill}"/>'
            f'<ofd:AbbreviatedData>{data}</ofd:AbbreviatedData></ofd:PathObject>')


def png():
    def chunk(name, data):
        return struct.pack('>I', len(data)) + name + data + struct.pack('>I', zlib.crc32(name + data))
    rows = bytearray()
    for y in range(100):
        rows.append(0)
        for x in range(160):
            rows.extend((28, 130, 174) if x < 80 else (242, 177, 55))
    return (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', 160, 100, 8, 2, 0, 0, 0))
            + chunk(b'IDAT', zlib.compress(rows)) + chunk(b'IEND', b''))


def build_demo(*, multiple_documents=False, broken_page=False, embedded_font=None):
    entries = {}
    bodies = ('<ofd:DocBody><ofd:DocInfo><ofd:DocID>00000000000000000000000000000001</ofd:DocID>'
              '<ofd:Title>SealVerify 合成阅读示例</ofd:Title><ofd:Creator>SealVerify</ofd:Creator>'
              '</ofd:DocInfo><ofd:DocRoot>Doc_0/Document.xml</ofd:DocRoot></ofd:DocBody>')
    if multiple_documents:
        bodies += ('<ofd:DocBody><ofd:DocInfo><ofd:DocID>00000000000000000000000000000002</ofd:DocID>'
                   '<ofd:Title>第二份合成文档</ofd:Title></ofd:DocInfo><ofd:DocRoot>Doc_1/Document.xml</ofd:DocRoot></ofd:DocBody>')
        entries['Doc_1/Document.xml'] = (f'<ofd:Document {NS}><ofd:CommonData><ofd:MaxUnitID>1000</ofd:MaxUnitID>'
            '<ofd:PageArea><ofd:PhysicalBox>0 0 210 297</ofd:PhysicalBox></ofd:PageArea>'
            '<ofd:PublicRes>../Doc_0/PublicRes.xml</ofd:PublicRes></ofd:CommonData>'
            '<ofd:Pages><ofd:Page ID="900" BaseLoc="Page.xml"/></ofd:Pages></ofd:Document>')
        entries['Doc_1/Page.xml'] = f'<ofd:Page {NS}><ofd:Content><ofd:Layer ID="901">{text(902, "第二份文档：包内文档切换成功")}</ofd:Layer></ofd:Content></ofd:Page>'
    entries['OFD.xml'] = f'<ofd:OFD {NS} Version="1.0" DocType="OFD">{bodies}</ofd:OFD>'
    page_refs = ''.join(f'<ofd:Page ID="{10+i}" BaseLoc="Pages/Page_{i}/Content.xml"/>' for i in range(4))
    entries['Doc_0/Document.xml'] = (f'<ofd:Document {NS}><ofd:CommonData><ofd:MaxUnitID>2000</ofd:MaxUnitID>'
        '<ofd:PageArea><ofd:PhysicalBox>0 0 210 297</ofd:PhysicalBox></ofd:PageArea>'
        '<ofd:PublicRes>PublicRes.xml</ofd:PublicRes><ofd:DocumentRes>DocumentRes.xml</ofd:DocumentRes>'
        '<ofd:TemplatePage ID="2" Name="页眉页脚" BaseLoc="Tpls/Template.xml"/>'
        f'</ofd:CommonData><ofd:Pages>{page_refs}</ofd:Pages>'
        '<ofd:Outlines><ofd:OutlineElem Title="中文与矢量图"><ofd:Actions><ofd:Action Event="CLICK"><ofd:Goto><ofd:Dest Type="XYZ" PageID="10" Left="0" Top="0"/></ofd:Goto></ofd:Action></ofd:Actions></ofd:OutlineElem>'
        '<ofd:OutlineElem Title="阅读终点"><ofd:Actions><ofd:Action Event="CLICK"><ofd:Goto><ofd:Dest Type="XYZ" PageID="13" Left="0" Top="0"/></ofd:Goto></ofd:Action></ofd:Actions></ofd:OutlineElem></ofd:Outlines>'
        '<ofd:Annotations>Annotations.xml</ofd:Annotations></ofd:Document>')
    fontfile = '<ofd:FontFile>font.otf</ofd:FontFile>' if embedded_font else ''
    entries['Doc_0/PublicRes.xml'] = (f'<ofd:Res {NS} BaseLoc="Res"><ofd:Fonts>'
        f'<ofd:Font ID="1" FontName="Noto Sans CJK SC" FamilyName="Noto Sans CJK SC">{fontfile}</ofd:Font>'
        '</ofd:Fonts></ofd:Res>')
    if embedded_font:
        entries['Doc_0/Res/font.otf'] = Path(embedded_font).read_bytes()
    entries['Doc_0/DocumentRes.xml'] = (f'<ofd:Res {NS} BaseLoc="Res"><ofd:MultiMedias>'
        '<ofd:MultiMedia ID="3" Type="Image" Format="PNG"><ofd:MediaFile>blocks.png</ofd:MediaFile>'
        '</ofd:MultiMedia></ofd:MultiMedias></ofd:Res>')
    entries['Doc_0/Res/blocks.png'] = png()
    entries['Doc_0/Tpls/Template.xml'] = (f'<ofd:Page {NS}><ofd:Area><ofd:PhysicalBox>0 0 210 297</ofd:PhysicalBox></ofd:Area><ofd:Content><ofd:Layer ID="4" Type="Background">'
        + text(5, 'SealVerify  /  OFD 阅读示例', y=10, size=3.5, color='100 115 130')
        + text(6, '人工合成文件 · 不含真实签章或业务信息', y=275, size=3.5, color='100 115 130')
        + '</ofd:Layer></ofd:Content></ofd:Page>')
    pages = [
        text(100, '你好，OFD。', size=9) + text(101, '01 / 中文文字、矢量图与模板页', y=48)
        + path(102, 'M 0 0 L 174 0 L 174 35 L 0 35 C', '18 80 174 35')
        + text(103, '文字清晰，页面保持原有版式。', x=25, y=90, size=5, color='255 255 255')
        + text(104, '使用左侧缩略图或工具栏继续阅读。', y=130)
        + text(105, '查找示例关键词：阅读测试', y=155)
        + path(106, 'M 0 35 B 10 0 55 0 65 35 L 0 35 C', '18 190 65 36', '242 177 55'),
        text(200, '02 / 图片、透明度与注释', size=7)
        + '<ofd:ImageObject ID="201" ResourceID="3" Boundary="18 65 160 100" CTM="160 0 0 100 0 0"/>'
        + text(202, '蓝色与黄色区域来自嵌入的 PNG 图片。', y=180)
        + path(203, 'M 0 0 L 65 0 L 65 22 L 0 22 C', '110 145 65 22', '220 35 55', extra='Alpha="130"')
        + text(204, '右下红色标记为合成注释，不是真实印章。', y=205, size=4),
        text(300, '03 / 多页连续阅读', size=7)
        + ''.join(text(310+i, f'第 {i+1:02} 行：阅读测试，支持全文查找与文字选择。', y=60+i*15, size=4) for i in range(12)),
        text(400, '04 / 横向页面', size=8)
        + text(401, '已到达最后一页。', y=65, size=7)
        + text(402, '文档包含四页，横向与纵向尺寸分别显示。', y=90)
        + path(403, 'M 0 0 L 250 0 L 250 30 L 0 30 C', '18 120 250 30', '23 92 99')
        + text(404, '阅读完成  /  END', x=30, y=128, size=7, color='255 255 255'),
    ]
    for i, content in enumerate(pages):
        area = '<ofd:Area><ofd:PhysicalBox>0 0 297 210</ofd:PhysicalBox></ofd:Area>' if i == 3 else '<ofd:Template TemplateID="2" ZOrder="Background"/>'
        entries[f'Doc_0/Pages/Page_{i}/Content.xml'] = (f'<ofd:Page {NS}>{area}<ofd:Content>'
            f'<ofd:Layer ID="{20+i}" Type="Body">{content}</ofd:Layer></ofd:Content></ofd:Page>')
    entries['Doc_0/Annotations.xml'] = f'<ofd:Annotations {NS}><ofd:Page PageID="11"><ofd:FileLoc>Annots/Page_1.xml</ofd:FileLoc></ofd:Page></ofd:Annotations>'
    entries['Doc_0/Annots/Page_1.xml'] = (f'<ofd:PageAnnot {NS}><ofd:Annot ID="500" Type="Stamp" Creator="SealVerify" '
        'LastModDate="2026-11-06" Visible="true"><ofd:Appearance Boundary="145 230 40 25">'
        + path(501, 'M 0 0 L 40 0 L 40 25 L 0 25 C', '0 0 40 25', '190 40 50')
        + '</ofd:Appearance></ofd:Annot></ofd:PageAnnot>')
    if broken_page:
        entries['Doc_0/Pages/Page_1/Content.xml'] = '<broken'
    output = BytesIO()
    with ZipFile(output, 'w') as archive:
        for name, data in entries.items():
            info = ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = ZIP_DEFLATED
            archive.writestr(info, data.encode('utf-8') if isinstance(data, str) else data)
    return output.getvalue()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    parser.add_argument('--multiple-documents', action='store_true')
    parser.add_argument('--broken-page', action='store_true')
    parser.add_argument('--embedded-font', type=Path)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(build_demo(multiple_documents=args.multiple_documents,
        broken_page=args.broken_page, embedded_font=args.embedded_font))
    print('已生成合成阅读样例：' + str(args.output))
