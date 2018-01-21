#!/usr/bin/python
#
# Copyright 2012 Google Inc. All Rights Reserved.

"""Simple script to interact with VirusTotal's file distribution API.

VirusTotal's file distribution API allows privileged users to download files
submitted to VirusTotal. It works over HTTP and makes use of json objects to
send back basic information on the submitted files that will allows the
client-side to decide whether a given file under consideration should be
downloaded. The API is documented at:
https://www.virustotal.com/documentation/private-api/#file-feed
"""

__author__ = 'emartinez@virustotal.com (Emiliano Martinez)'


import calendar
import json
import logging
import os
import Queue
import re
import socket
import sys
import threading
import time
import urllib


API_KEY = ''  # Insert your API here
API_URL = ('https://www.virustotal.com/vtapi/v2/file/distribution'
           '?after=%s&limit=%s&apikey=%s')
API_BATCH_SIZE = 1000

NUM_CONCURRENT_DOWNLOADS = 20
MAX_DOWNLOAD_ATTEMPTS = 3
LOCAL_STORE = 'vtfiles'

HEX_CHARACTERS = 'abcdef0123456789'

socket.setdefaulttimeout(10)

LOGGING_LEVEL = logging.INFO  # Modify if you just want to focus on errors
logging.basicConfig(level=LOGGING_LEVEL,
                    format='%(asctime)s %(levelname)-8s %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    stream=sys.stdout)


def create_local_store():
  """Creates 3 level directory structure to store downloaded files.

  In order to avoid filesystem problems and latency the files are stored
  in a three level directory structure, first directory is the first character
  of the sha256, second, and third.
  """
  if not os.path.exists(LOCAL_STORE):
    os.mkdir(LOCAL_STORE)
  for char0 in HEX_CHARACTERS:
    dir0 = os.path.join(LOCAL_STORE, char0)
    if not os.path.exists(dir0):
      os.mkdir(dir0)
    for char1 in HEX_CHARACTERS:
      dir1 = os.path.join(dir0, char1)
      if not os.path.exists(dir1):
        os.mkdir(dir1)
      for char2 in HEX_CHARACTERS:
        dir2 = os.path.join(dir1, char2)
        if not os.path.exists(dir2):
          os.mkdir(dir2)


def current_after():
  """Retrieves the current after value from persistent storage.

  VirusTotal's distribution API is based on a sliding window approach with and
  after parameters that allows you to paginate over all the files submitted
  after a given timestamp. The first time this script is launched the current
  after is read from disk.

  Returns:
    Last after value stored in disk, as a string. If the script was never
    launched before or the script's memory was deleted it will return the
    current timestamp minus 3 hours.
  """
  after = ''
  if os.path.exists('vtfiles.memory'):
    # Retrieve the stored after pointer.
    with open('vtfiles.memory', 'r') as memory:
      after = memory.read().strip()

  if not re.match('[0-9]+$', after):
    # We do not know where we were at, just fix after to be 3 hours before the
    # current GMT epoch.
    after = '%s' % ((calendar.timegm(time.gmtime()) - 3 * 3600) * 1000)

  return after


def store_after(after):
  """Stores the current after value to disk.

  Every so often the current sliding window pointer is stored to disk in order
  to make sure that if the script is stopped or dies it will know where to
  start at the next time it is launched.

  Args:
    after: after value (string) to save in a memory file.
  """
  with open('vtfiles.memory', 'w') as memory:
    memory.write(after)


def get_download_candidates(after=0, limit=API_BATCH_SIZE):
  """Asks VirusTotal's file feed API for files to download.

  Interacts with:
    https://www.virustotal.com/documentation/private-api/#file-feed
  Asking for files in a given distribution queue that have arrived to VirusTotal
  after the timestamp <after>. The API answers back with a json object per
  queued file, the json object contains basic information about the file as well
  as a link to download it.

  Args:
    after: timestamp that filters the items to retrieve, only files submitted
      after this timestamp will be retrieved.
    limit: number of items to retrieve from the queue that comply with the
      previous condition.

  Returns:
    List of json objects containing the basic information about each file
    retrieved. None if there was an error with the request.
  """
  try:
    response = urllib.urlopen(API_URL % (after, limit, API_KEY)).read()
  # Should not catch such a general exception, but who knows what can go
  # on in the client-side.
  except Exception:
    return

  try:
    candidates = json.loads(response)
  except ValueError:
    return

  return candidates


def detection_ratio(report):
  """Calculates the detection ratio of a given VirusTotal scan report.

  Processes the report dictionary structure of the file distribution API call
  response and produces a number of positives and a total number of engines
  tha scanned the file.

  Args:
    report: AV scan dictionary structure, as returned by the file distribution
      API call.

  Returns:
    Tuple with two items, the first one being the number of AV solutions that
    detected the file and the second one being the total number of AV engines
    that scanned it. Returns None if the report is not valid.
  """
  if not report:
    return

  total = len(report)
  positives = len([x[0] for x in report.values() if x[0] and x[0] != '-'])
  return (positives, total)


def filter_candidate(candidate):
  """Decides whether a given download candidate should be downloaded.

  This function allows the user to parametrize the files he is interested in
  and download exclusively those. For example, certain users might only want
  to download Portable Executable files, others may only be interested in files
  with more than N positives, etc.

  Args:
    candidate: dictionary with basic information on a file received at
      VirusTotal.

  Returns:
    True if the canidate should be ignored and not downloaded, False if it
    meets our requirements and it must be downloaded.
  """
  # Filters candidates with less than 2 positives.
  report = candidate.get('report')
  if report and detection_ratio(report)[0] == 2:
    return True
  # Filter candidates with a size over 32MB
  if candidate.get('size', 0) > 32 * 1024 * 1024:
    return True
  # Filters candidates that are not Win32 Executables.
  #if candidate.get('type') != 'Win32 EXE':
  #  return True
  return False


def download_candidate(candidate):
  """Downloads a given file from VirusTotal to the local store.

  Files are stored locally in a 3 level directory structure in order to avoid
  acess latency.

  Args:
    candidate: dictionary with basic information on a file received at
      VirusTotal.

  Returns:
    True if the file was successfully downloaded, False if not.
  """
  if not 'link' in candidate or not 'sha256' in candidate:
    return False

  sha256 = candidate.get('sha256')
  download_url = candidate.get('link')
  target = os.path.join(LOCAL_STORE, sha256[0], sha256[1], sha256[2], sha256)
  attempts = 0
  while attempts < MAX_DOWNLOAD_ATTEMPTS:
    try:
      urllib.urlretrieve(download_url, target)
      return True
    # Should not catch such a general exception, but who knows what can go
    # on in the client-side.
    except Exception:
      attempts += 1
  return False


def process_candidate(candidate):
  """Allows the user to perform a custom action with the downloaded file.

  This function is called after a file has been successfully downloaded to the
  local store. It might be used to insert the file data into a local database,
  to trigger another process, etc. My recommendation is that this function
  should be as lightweight and quick as possible so that the download process
  is not delayed, hence, anything you do here should be done asynchronously.
  You might want to launch an asynchronous thread or some external process and
  return immediatelly.

  Args:
    candidate: dictionary with basic information on a file received at
      VirusTotal.

  Returns:
    True if the post-processing was successful, False if not.
  """
  return True


def main():
  """Main routine, thread pool to retrieve VT files and download them."""
  logging.info('Initializing VirusTotal file feed downloader')
  logging.info('Creating local store if necessary')
  create_local_store()

  work = Queue.Queue()  # Queues download candidates
  end_process = False

  def worker():
    while not end_process:
      try:
        candidate = work.get(True, 5)
      except Queue.Empty:
        continue
      sha256 = candidate.get('sha256', 'file').lower()
      logging.info('Handling download candidate %s', sha256)
      if not filter_candidate(candidate):
        logging.info('Downloading %s', sha256)
        success = download_candidate(candidate)
        if success:
          logging.info('%s download successful', sha256)
          logging.info('Post-processing %s', sha256)
          success = process_candidate(candidate)
          if success:
            logging.info('%s post-processing was sucessful', sha256)
          else:
            logging.error('%s post-processing failed', sha256)
        else:
          logging.error('%s download failed', sha256)
      else:
        logging.info('%s was filtered', sha256)
      work.task_done()

  threads = []
  for unused_index in range(NUM_CONCURRENT_DOWNLOADS):
    thread = threading.Thread(target=worker)
    thread.daemon = True
    thread.start()
    threads.append(thread)

  logging.info('Retrieving current sliding window pointer')
  after = current_after()
  iterations = 0
  while not end_process:
    try:
      if work.qsize() > 300:
        logging.info('Too many files waiting to be downloaded, sleeping')
        time.sleep(30)
        continue
      logging.info('Retrieving download candidates received after %s', after)
      candidates = get_download_candidates(after)
      if candidates is None:
        logging.error('Could not retrieve download candidates')
        time.sleep(10)
        continue
      if candidates:
        iterations += 1
        after = '%s' % candidates[-1].get('timestamp')
        logging.info('Retrieved %s candidates, queuing them', len(candidates))
        for candidate in candidates:
          work.put(candidate)
      else:
        logging.info('No more download candidates, sleeping')
        time.sleep(30)
      if iterations == 2:  # Every once in a while store current after
        store_after(after)
        iterations = 0
    except KeyboardInterrupt:
      end_process = True
      logging.info('Stopping the downloader, current downloads must end, '
                   'please wait...')
      for thread in threads:
        if thread.is_alive():
          thread.join()


if __name__ == '__main__':
  main()
