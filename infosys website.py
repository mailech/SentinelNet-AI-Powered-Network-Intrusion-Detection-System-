import sys
from youtube_transcript_api import YouTubeTranscriptApi
import urllib.request
import re

video_id = 'z1sGAxOkQEA'
url = f"https://www.youtube.com/watch?v={video_id}"

try:
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    html = urllib.request.urlopen(req).read().decode('utf-8')
    title_match = re.search(r'<title>(.*?)</title>', html)
    title = title_match.group(1) if title_match else "Unknown"
    
    desc_match = re.search(r'"shortDescription":"(.*?)"', html)
    if desc_match:
        desc = desc_match.group(1).replace('\\n', '\n')
    else:
        desc_match = re.search(r'<meta name="description" content="(.*?)">', html)
        desc = desc_match.group(1) if desc_match else "Unknown"
except Exception as e:
    title, desc = str(e), str(e)

with open('yt_context.txt', 'w', encoding='utf-8') as f:
    f.write(f"TITLE: {title}\nDESCRIPTION:\n{desc}\n\nTRANSCRIPT:\n")
    try:
        transcript = YouTubeTranscriptApi.get_transcript(video_id)
        for entry in transcript:
            f.write(f"{entry['text']} ")
    except Exception as e:
        f.write(f"Error fetching transcript: {e}\n")
