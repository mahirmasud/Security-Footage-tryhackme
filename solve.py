import os
import re
from scapy.all import rdpcap, TCP, Raw
import subprocess
from pathlib import Path

def extract_frames(pcap_file="c.pcap"):
    print(f"Processing {pcap_file}...")
    packets = rdpcap(pcap_file)
    tcp_payloads = bytearray()
    boundary = b"--BoundaryString"
    frame_count = 0

    # Extract all TCP payloads
    for pkt in packets:
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            tcp_payloads.extend(pkt[Raw].load)

    print(f"Found {len(tcp_payloads)} bytes of TCP data")
    
    # Create output directory
    os.makedirs("extracted_frames", exist_ok=True)

    # Process MJPEG stream
    start = 0
    while (start := tcp_payloads.find(boundary, start)) != -1:
        end = tcp_payloads.find(boundary, start + len(boundary))
        if end == -1:
            break

        chunk = tcp_payloads[start:end]
        
        # Check for JPEG content
        if b"image/jpeg" not in chunk:
            start = end
            continue

        # Extract JPEG data
        header_end = chunk.find(b"\r\n\r\n")
        if header_end == -1:
            start = end
            continue

        jpeg_data = chunk[header_end+4:]
        output_path = f"extracted_frames/frame_{frame_count:04d}.jpg"
        
        with open(output_path, "wb") as f:
            f.write(jpeg_data)
        
        frame_count += 1
        start = end

    print(f"Extracted {frame_count} JPEG frames")
    return frame_count

def create_video(fps=15):
    if not os.path.exists("extracted_frames"):
        print("No frames to process!")
        return

    cmd = [
        "ffmpeg",
        "-y",  # Overwrite without asking
        "-framerate", str(fps),
        "-i", "extracted_frames/frame_%04d.jpg",
        "-c:v", "libx264",
        "-crf", "22",  # Quality balance
        "-pix_fmt", "yuv420p",
        "output.mp4"
    ]

    try:
        subprocess.run(cmd, check=True)
        print("Video created: output.mp4")
    except subprocess.CalledProcessError as e:
        print(f"FFmpeg failed: {e}")
    except FileNotFoundError:
        print("Error: ffmpeg not found. Please install ffmpeg.")

if __name__ == "__main__":
    frame_count = extract_frames()
    if frame_count > 0:
        create_video()
