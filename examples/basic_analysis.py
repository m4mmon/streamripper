#!/usr/bin/env python3
"""
Basic example of using streamripper to analyze an RTSP stream.

This example demonstrates:
- Basic stream analysis
- Chart generation
- Error handling
"""

import os
import sys
from datetime import datetime

# Add the src directory to the path for development
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from streamripper import analyze_rtsp_stream, generate_video_chart


def main():
    """Run a basic stream analysis example."""
    # Configuration
    rtsp_url = "rtsp://example.com/stream"  # Replace with your RTSP URL
    duration = 30  # seconds
    output_dir = "./output"
    
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Generate timestamp prefix
    timestamp_prefix = f"example_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    print(f"Starting analysis of {rtsp_url}")
    print(f"Duration: {duration} seconds")
    print(f"Output directory: {output_dir}")
    print("-" * 50)
    
    try:
        # Analyze the stream
        data = analyze_rtsp_stream(
            rtsp_url=rtsp_url,
            duration=duration,
            output_dir=output_dir,
            debug_log=True,
            timestamp_prefix=timestamp_prefix,
            save_stream=False  # Set to True to save raw stream
        )
        
        if data is not None and not data.empty:
            print(f"Analysis completed successfully!")
            print(f"Analyzed {len(data)} frames")
            
            # Generate visualization
            generate_video_chart(
                output_dir=output_dir,
                data=data,
                timestamp_prefix=timestamp_prefix
            )
            
            print(f"Chart generated successfully!")
            print(f"Files saved with prefix: {timestamp_prefix}")
            
        else:
            print("No data was collected during analysis.")
            
    except Exception as e:
        print(f"Error during analysis: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
