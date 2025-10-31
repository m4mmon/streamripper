#!/usr/bin/env python3
"""
Multi-stream analysis demonstration.

This example shows how streamripper organizes outputs by sanitized URL,
making it easy to manage multiple streams and query historical data.
"""

import os
import sys
import glob
from datetime import datetime

# Add the src directory to the path for development
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from streamripper import analyze_rtsp_stream, generate_comprehensive_chart, sanitize_url_for_filename


def analyze_multiple_streams_demo():
    """Demonstrate organized multi-stream analysis."""
    
    # Example streams (replace with your actual streams)
    streams = [
        "rtsp://thingino:thingino@192.168.88.33/ch0",
        # Add more streams here for real testing:
        # "rtsp://admin:password@192.168.1.100/stream1",
        # "rtsp://user@camera.example.com:554/live/main",
    ]
    
    base_output_dir = "./multi_stream_output"
    duration = 15  # Short duration for demo
    
    print("🎥 Multi-Stream Analysis Demo")
    print("=" * 50)
    print(f"Base output directory: {base_output_dir}")
    print(f"Analysis duration: {duration} seconds per stream")
    print(f"Streams to analyze: {len(streams)}")
    print()
    
    results = {}
    
    for i, stream_url in enumerate(streams, 1):
        print(f"📡 Analyzing Stream {i}/{len(streams)}")
        print(f"URL: {stream_url}")
        
        # Show how URL gets sanitized
        sanitized = sanitize_url_for_filename(stream_url)
        stream_dir = os.path.join(base_output_dir, sanitized)
        print(f"Directory: {stream_dir}")
        
        timestamp_prefix = f"demo_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        try:
            # Analyze the stream
            data = analyze_rtsp_stream(
                rtsp_url=stream_url,
                duration=duration,
                output_dir=base_output_dir,  # Base dir - function creates organized subdirs
                debug_log=True,
                timestamp_prefix=timestamp_prefix,
                save_stream=True  # Save raw stream for demo purposes
            )
            
            if data is not None and not data.empty:
                # Generate comprehensive chart
                generate_comprehensive_chart(
                    output_dir=stream_dir,  # Direct to organized directory
                    data=data,
                    timestamp_prefix=timestamp_prefix
                )
                
                results[stream_url] = {
                    'status': 'success',
                    'frames': len(data),
                    'directory': stream_dir,
                    'timestamp': timestamp_prefix
                }
                print(f"✅ Success: {len(data)} packets analyzed")
                
            else:
                results[stream_url] = {'status': 'no_data'}
                print("❌ No data collected")
                
        except Exception as e:
            results[stream_url] = {'status': 'error', 'error': str(e)}
            print(f"❌ Error: {e}")
        
        print("-" * 30)
    
    return results, base_output_dir


def query_historical_data(base_output_dir):
    """Demonstrate querying historical analysis data."""
    print("\n📊 Historical Data Query Demo")
    print("=" * 50)
    
    if not os.path.exists(base_output_dir):
        print("No historical data found.")
        return
    
    # Find all stream directories
    stream_dirs = [d for d in os.listdir(base_output_dir) 
                   if os.path.isdir(os.path.join(base_output_dir, d)) and d.startswith('rtsp_')]
    
    if not stream_dirs:
        print("No stream directories found.")
        return
    
    print(f"Found {len(stream_dirs)} stream sources:")
    print()
    
    for stream_dir in sorted(stream_dirs):
        full_path = os.path.join(base_output_dir, stream_dir)
        print(f"📁 {stream_dir}")
        
        # Find all analysis files for this stream
        csv_files = glob.glob(os.path.join(full_path, "*_flow.csv"))
        report_files = glob.glob(os.path.join(full_path, "*_report.txt"))
        chart_files = glob.glob(os.path.join(full_path, "*_chart_*.png"))
        
        print(f"   📈 Analysis sessions: {len(csv_files)}")
        print(f"   📄 Reports: {len(report_files)}")
        print(f"   🎨 Charts: {len(chart_files)}")
        
        # Show latest files
        if csv_files:
            latest_csv = max(csv_files, key=os.path.getctime)
            timestamp = os.path.basename(latest_csv).split('_')[1:3]
            print(f"   🕒 Latest analysis: {'_'.join(timestamp)}")
        
        print()


def main():
    """Run the multi-stream demonstration."""
    print("🚀 Streamripper Multi-Stream Organization Demo")
    print("=" * 60)
    
    # Analyze streams
    results, base_dir = analyze_multiple_streams_demo()
    
    # Show results summary
    print("\n📋 Analysis Summary")
    print("=" * 30)
    successful = sum(1 for r in results.values() if r['status'] == 'success')
    print(f"✅ Successful: {successful}")
    print(f"❌ Failed: {len(results) - successful}")
    
    # Query historical data
    query_historical_data(base_dir)
    
    print("\n🎯 Key Benefits of Organized Output:")
    print("• Automatic credential removal for security")
    print("• Filesystem-safe directory names")
    print("• Easy multi-stream management")
    print("• Historical data preservation per source")
    print("• Simple querying and analysis")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
