#!/usr/bin/env python3
"""
Batch analysis example for multiple RTSP streams.

This example demonstrates:
- Analyzing multiple streams
- Batch processing
- Results comparison
"""

import os
import sys
from datetime import datetime
import time

# Add the src directory to the path for development
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from streamripper import analyze_rtsp_stream, generate_video_chart


def analyze_multiple_streams(streams, duration=30, output_base_dir="./batch_output"):
    """
    Analyze multiple RTSP streams and generate reports.
    
    Args:
        streams (list): List of RTSP URLs to analyze
        duration (int): Analysis duration in seconds
        output_base_dir (str): Base directory for outputs
    """
    results = {}
    
    for i, stream_url in enumerate(streams, 1):
        print(f"\n{'='*60}")
        print(f"Analyzing stream {i}/{len(streams)}: {stream_url}")
        print(f"{'='*60}")
        
        # Note: streamripper now automatically organizes outputs by sanitized URL
        # No need to create manual stream directories
        
        # Generate timestamp prefix
        timestamp_prefix = f"{stream_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        try:
            # Analyze the stream
            data = analyze_rtsp_stream(
                rtsp_url=stream_url,
                duration=duration,
                output_dir=output_dir,
                debug_log=True,
                timestamp_prefix=timestamp_prefix
            )
            
            if data is not None and not data.empty:
                # Generate visualization
                generate_video_chart(
                    output_dir=output_dir,
                    data=data,
                    timestamp_prefix=timestamp_prefix
                )
                
                # Store results
                results[stream_url] = {
                    'status': 'success',
                    'frames': len(data),
                    'output_dir': output_dir,
                    'timestamp_prefix': timestamp_prefix
                }
                
                print(f"✓ Analysis completed: {len(data)} frames analyzed")
                
            else:
                results[stream_url] = {
                    'status': 'no_data',
                    'error': 'No data collected'
                }
                print("✗ No data collected")
                
        except Exception as e:
            results[stream_url] = {
                'status': 'error',
                'error': str(e)
            }
            print(f"✗ Error: {e}")
        
        # Small delay between analyses
        if i < len(streams):
            print("Waiting 5 seconds before next analysis...")
            time.sleep(5)
    
    return results


def print_summary(results):
    """Print a summary of batch analysis results."""
    print(f"\n{'='*60}")
    print("BATCH ANALYSIS SUMMARY")
    print(f"{'='*60}")
    
    successful = sum(1 for r in results.values() if r['status'] == 'success')
    failed = len(results) - successful
    
    print(f"Total streams analyzed: {len(results)}")
    print(f"Successful: {successful}")
    print(f"Failed: {failed}")
    
    print(f"\nDetailed Results:")
    print("-" * 40)
    
    for stream_url, result in results.items():
        status_icon = "✓" if result['status'] == 'success' else "✗"
        print(f"{status_icon} {stream_url}")
        
        if result['status'] == 'success':
            print(f"   Frames: {result['frames']}")
            print(f"   Output: {result['output_dir']}")
        else:
            print(f"   Error: {result.get('error', 'Unknown error')}")
        print()


def main():
    """Run batch analysis example."""
    # Example stream URLs (replace with your actual streams)
    streams = [
        "rtsp://example1.com/stream",
        "rtsp://example2.com/stream", 
        "rtsp://example3.com/stream",
    ]
    
    duration = 30  # seconds per stream
    output_dir = "./batch_output"
    
    print("Starting batch analysis...")
    print(f"Streams to analyze: {len(streams)}")
    print(f"Duration per stream: {duration} seconds")
    print(f"Output directory: {output_dir}")
    
    # Run batch analysis
    results = analyze_multiple_streams(streams, duration, output_dir)
    
    # Print summary
    print_summary(results)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
