#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
    @Time    :   2020/6/18,
    @Author  :   Yiling He,
    @Version :   1.0,
    @Contact :   heyilinge0@gmail.com,
'''

import os
import sys
import json
import pandas as pd
import argparse
import logging
import time
from datetime import datetime
from tqdm import tqdm
import asyncio
import aiohttp
from tenacity import retry, stop_after_attempt, before_log

parser = argparse.ArgumentParser(description='Androzoo downloader script.')
parser.add_argument('year', type=int, help='Choose a specific year.')
parser.add_argument('--update', type=bool, default=False, help='Ignore the downloaded.')
parser.add_argument('--max', type=int, default=104000, help='Max number of apks to download.')
parser.add_argument('--coroutine', type=int, default=20, help='Number of coroutines.')
parser.add_argument('--markets', nargs='+', default=['play.google.com', 'anzhi', 'appchina'], help='Number of coroutines.')
parser.add_argument('--vt_detection', type=int, default=0, help='Download Benign apks by default. Lower bound (included) of `Malware` if greater than 0.')
parser.add_argument('--upper', type=int, help='Upper bound (not included) for `Malware`. Useful only if vt_detection is greater than 0.')
parser.add_argument('--output', type=str, default='data1', help='Save apks in /<output>/Androzoo/<Benign or Malware_LB>/<year>.')
parser.add_argument('--debug', type=bool, default=False, help='Logging level: INFO by default, DEBUG will log for every apk in both stdout and file.')

args = parser.parse_args()
year = args.year

if args.vt_detection == 0:
    cat = 'Benign'
    print('[AndrozooDownloader] Benign Samples.')
else:
    cat = ('Malware_%d-%d' % (args.vt_detection, args.upper)) if args.upper else ('Malware_%d' % args.vt_detection)
    if args.upper:
        print('[AndrozooDownloader] Malware Samples (%d<=vt_detection<%d).' % (args.vt_detection, args.upper))
    else:
        print('[AndrozooDownloader] Malware Samples (vt_detection>=%d).' % args.vt_detection)
outdir = '/%s/Androzoo/%s/%d' % (args.output, cat, year)
if not os.path.exists(outdir):
    os.makedirs(outdir)

timestamp = int(round(time.time() * 1000))
tag = '%d_%s_%d' % (year, cat, timestamp)
log_file = '%s.log' % tag
LOG_FORMAT = '%(asctime)s - %(levelname)s - %(message)s'
fmt = logging.Formatter(LOG_FORMAT)

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
if not args.debug:
    filelog_level = logging.INFO
else:
    filelog_level = logging.DEBUG
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setLevel(logging.DEBUG)
    stream_handler.setFormatter(fmt)
    logger.addHandler(stream_handler)
file_handler = logging.FileHandler(log_file)
file_handler.setLevel(filelog_level)
file_handler.setFormatter(fmt)
logger.addHandler(file_handler)


def read_config(fname='config'):
    with open(fname, 'r') as f:
        config = json.load(f)
    return config


def filter(year, a, processed):
    if cat == 'Benign':
        a = a[a.vt_detection == 0]
    else:
        a = a[a.vt_detection >= args.vt_detection]
        if args.upper:
            a = a[a.vt_detection < args.upper]
    date = pd.to_datetime(a['dex_date'])
    a = a.assign(dex_date=date)
    a = a[(a.dex_date > datetime(year,1,1)) & (a.dex_date < datetime(year+1,1,1))]

    print('[AndrozooDownloader] Selecting from markets: ', args.markets)
    pattern = ' | '.join(["(a.markets.str.contains('%s'))" % i for i in args.markets])
    # (a.markets.str.contains('play.google.com')) | (a.markets.str.contains('anzhi')) | (a.markets.str.contains('anzhi'))
    a = a[eval(pattern)]
    logging.info('%d APKs in total for year %d' % (len(a), year))
    a.to_csv(processed, index=False)
    return a

@retry(stop=stop_after_attempt(3), before=before_log(logging.getLogger(), logging.DEBUG))
async def download(sha256, config, session, chunk_size=1024):
    base_url = 'https://androzoo.uni.lu/api/download?apikey={0}&sha256={01}'
    url = base_url.format(config['key'], sha256)

    if 'proxy' in config.keys():
        ip = config['proxy']
        port = config['port']
        proxy = "http://%s:%d" % (ip, port)

        # logging.debug('Requesting %s...' % sha256)
        async with session.get(url, proxy=proxy, timeout=None) as response:
            with open('%s/%s.apk' % (outdir, sha256), 'wb') as f:
                while True:
                    chunk = await response.content.read(chunk_size)
                    if not chunk:
                        break
                    f.write(chunk)
            logging.debug('[Success] %s' % sha256)
            with open('%s.txt' % tag, 'a') as log:
                log.write('%s\n' % sha256)

    else:
        async with session.get(url) as response:
            with open('%s/%s.apk' % (outdir, sha256), 'wb') as f:
                while True:
                    chunk = await response.content.read(chunk_size)
                    if not chunk:
                        break
                    f.write(chunk)
            logging.debug('[Success] %s' % sha256)
            with open('%s.txt' % tag, 'a') as log:
                log.write('%s\n' % sha256)


async def cordownload(batch, i, config):
    logging.info('No.%d coroutine: downloading %d apks...' % (i, len(batch)))
    async with aiohttp.ClientSession(raise_for_status=True) as session:
        for sha256 in tqdm(batch, desc='[Coroutine %d]' % i):
            # print('No.%d coroutine' % i)
            logging.debug('[Start] No.%d coroutine: %s' % (i, sha256))
            await download(sha256, config, session)

if __name__ == '__main__':
    config = read_config()

    processed = '%d_%s.csv' % (year, cat)
    if not os.path.exists(processed):
        meta = pd.read_csv(config['meta'])
        meta = filter(year, meta, processed)
    else:
        meta = pd.read_csv(processed)
    if args.update:
        import glob
        exist = glob.glob('%d_*.txt' % year)
        df = pd.DataFrame()
        for i in exist:
            df = df.append(pd.read_csv(i, header=None))
        meta = meta[~meta.sha256.isin(df[0].to_list())]

        broken = pd.DataFrame([i.split('/')[-1][:-4] for i in glob.glob('%s/*.apk'%outdir)])
        broken = broken[~broken[0].isin(df[0])]
        for b in broken[0]:
            os.remove('%s/%s.apk' % (outdir, b))
            logging.info('[Remove] BROKEN %s/%s.apk' % (outdir, b))
            print('[AndrozooDownloader] Removing broken %s/%s.apk' % (outdir, b))

        logging.info('[Update] %d already exist. Continue downloading %d apks.' % (len(df), len(meta)))
        print('[AndrozooDownloader] %d already exist. %d remained.' % (len(df), len(meta)))
    
    if args.max:
        if len(meta) > args.max:
            logging.info('[Sample] %d apks for downloading task.' % args.max)
            print('[AndrozooDownloader] Sample %d apks.' % args.max)
            meta = meta.sample(args.max)

    cornum = args.coroutine
    apks = meta.sha256.to_list()
    if len(apks) == 0:
        print('[AndrozooDownloader] No apk satisfied.')
    else:
        if args.coroutine > len(apks):
            cornum = len(apks)
            print('[AndrozooDownloader] Using %d coroutines.' % cornum)
        print('[AndrozooDownloader] %d apks for downloading task.' % len(apks))
        batches = []
        batches.extend([apks[i:i+cornum] for i in range(0, len(apks), cornum)])
        batches = pd.DataFrame(batches)
        
        loop = asyncio.get_event_loop()
        tasks = [cordownload(batches[i].dropna(), i, config) for i in range(cornum)]
        loop.run_until_complete(asyncio.wait(tasks))
