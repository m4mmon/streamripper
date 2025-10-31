#!/usr/bin/env python3
"""
Command-line interface for streamripper.

This module provides the main entry point for the streamripper command-line tool.
"""

import argparse
import sys
import os
from datetime import datetime

from .rtsp_analyzer import analyze_rtsp_stream, sanitize_url_for_filename
from .chart_generator import generate_combined_chart, generate_video_chart, generate_audio_chart, generate_comprehensive_chart


def create_parser():
    """Create and configure the argument parser."""
    parser = argparse.ArgumentParser(
        description="Streamripper - RTSP stream analyzer and video quality assessment tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  streamripper rtsp://example.com/stream
  streamripper rtsp://example.com/stream --duration 60
  streamripper rtsp://example.com/stream --output-dir ./analysis
  streamripper rtsp://example.com/stream --duration 60 --debug-log --timestamp-prefix test
        """
    )
    
    parser.add_argument(
        "rtsp_url",
        help="RTSP stream URL to analyze"
    )
    
    parser.add_argument(
        "--duration", "-d",
        type=int,
        default=30,
        help="Analysis duration in seconds (default: 30)"
    )
    
    parser.add_argument(
        "--output-dir", "-o",
        type=str,
        default="./output",
        help="Output directory for results (default: ./output)"
    )
    
    parser.add_argument(
        "--debug-log",
        action="store_true",
        help="Enable detailed debug logging"
    )
    
    parser.add_argument(
        "--timestamp-prefix", "-p",
        type=str,
        default=None,
        help="Custom prefix for output files (default: auto-generated)"
    )
    
    parser.add_argument(
        "--no-chart",
        action="store_true",
        help="Skip chart generation"
    )

    parser.add_argument(
        "--chart-type",
        choices=["combined", "separate", "video-only", "audio-only", "comprehensive"],
        default="combined",
        help="Type of chart to generate (default: combined)"
    )
    
    parser.add_argument(
        "--version", "-v",
        action="version",
        version="streamripper 0.1.0"
    )
    
    return parser


def main():
    """Main entry point for the CLI."""
    parser = create_parser()
    args = parser.parse_args()
    
    # Create output directory if it doesn't exist
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Generate timestamp prefix if not provided
    if args.timestamp_prefix is None:
        args.timestamp_prefix = f"analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    print("Streamripper - RTSP Stream Analyzer")
    print("=" * 40)
    print(f"Stream URL: {args.rtsp_url}")
    print(f"Duration: {args.duration} seconds")
    print(f"Output directory: {args.output_dir}")
    print(f"Debug logging: {'enabled' if args.debug_log else 'disabled'}")
    print(f"Chart generation: {'disabled' if args.no_chart else f'enabled ({args.chart_type})'}")
    print(f"Timestamp prefix: {args.timestamp_prefix}")
    print("-" * 40)
    
    try:
        # Analyze the stream
        print("Starting stream analysis...")
        data = analyze_rtsp_stream(
            rtsp_url=args.rtsp_url,
            duration=args.duration,
            output_dir=args.output_dir,
            debug_log=args.debug_log,
            timestamp_prefix=args.timestamp_prefix
        )
        
        if data is not None and not data.empty:
            print(f"✓ Analysis completed successfully!")
            print(f"  Frames analyzed: {len(data)}")

            # Calculate the organized output directory (same as in analyze_rtsp_stream)
            sanitized_url = sanitize_url_for_filename(args.rtsp_url)
            stream_output_dir = os.path.join(args.output_dir, sanitized_url)

            # Generate chart unless disabled
            if not args.no_chart:
                print(f"Generating {args.chart_type} chart...")

                if args.chart_type == "combined":
                    generate_combined_chart(
                        output_dir=stream_output_dir,
                        data=data,
                        timestamp_prefix=args.timestamp_prefix
                    )
                elif args.chart_type == "separate":
                    # Generate both video and audio charts
                    video_data = data[data['Type'].isin(['I', 'P', 'B'])]
                    audio_data = data[data['Type'] == 'A']

                    if not video_data.empty:
                        generate_video_chart(
                            output_dir=stream_output_dir,
                            data=video_data,
                            timestamp_prefix=args.timestamp_prefix
                        )

                    if not audio_data.empty:
                        generate_audio_chart(
                            output_dir=stream_output_dir,
                            data=audio_data,
                            timestamp_prefix=args.timestamp_prefix
                        )
                elif args.chart_type == "video-only":
                    video_data = data[data['Type'].isin(['I', 'P', 'B'])]
                    if not video_data.empty:
                        generate_video_chart(
                            output_dir=stream_output_dir,
                            data=video_data,
                            timestamp_prefix=args.timestamp_prefix
                        )
                elif args.chart_type == "audio-only":
                    audio_data = data[data['Type'] == 'A']
                    if not audio_data.empty:
                        generate_audio_chart(
                            output_dir=stream_output_dir,
                            data=audio_data,
                            timestamp_prefix=args.timestamp_prefix
                        )
                elif args.chart_type == "comprehensive":
                    generate_comprehensive_chart(
                        output_dir=stream_output_dir,
                        data=data,
                        timestamp_prefix=args.timestamp_prefix
                    )

                print("✓ Chart generated successfully!")
            
            print(f"\nResults saved with prefix: {args.timestamp_prefix}")
            print(f"Stream directory: {stream_output_dir}")
            print(f"Base output directory: {args.output_dir}")
            
        else:
            print("✗ No data was collected during analysis.")
            return 1
            
    except KeyboardInterrupt:
        print("\n✗ Analysis interrupted by user.")
        return 1
    except Exception as e:
        print(f"✗ Error during analysis: {e}")
        if args.debug_log:
            import traceback
            traceback.print_exc()
        return 1
    
    print("\nAnalysis completed successfully!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
