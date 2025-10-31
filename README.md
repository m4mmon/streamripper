# Streamripper

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

Streamripper is a powerful RTSP stream analyzer and video quality assessment tool. It provides comprehensive analysis of video streams, including frame analysis, timing drift detection, and visual reporting capabilities.

## Features

- **RTSP Stream Analysis**: Analyze live RTSP video streams in real-time
- **Frame Type Detection**: Identify I-frames, P-frames, and B-frames
- **Quality Metrics**: Calculate frame sizes, timing drift, and stream statistics
- **Visual Reports**: Generate comprehensive charts and graphs
- **CSV Export**: Export analysis data for further processing
- **Flexible Duration**: Analyze streams for custom time periods
- **Debug Logging**: Detailed logging for troubleshooting

## Installation

### Prerequisites

- Python 3.8 or higher
- FFmpeg libraries (for av package)

#### Installing FFmpeg

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install ffmpeg libavformat-dev libavcodec-dev libavdevice-dev libavutil-dev libswscale-dev libswresample-dev
```

**macOS:**
```bash
brew install ffmpeg
```

**Windows:**
Download FFmpeg from [https://ffmpeg.org/download.html](https://ffmpeg.org/download.html)

### Recommended Installation (using uv)

[uv](https://docs.astral.sh/uv/) is the fastest Python package manager and provides excellent virtual environment management. It's the recommended way to install and work with Streamripper.

#### Install uv (if not already installed)

```bash
# On macOS and Linux
curl -LsSf https://astral.sh/uv/install.sh | sh

# On Windows
powershell -c "irm https://astral.sh/uv/install.ps1 | iex"

# Or using pip
pip install uv
```

#### Basic Installation

```bash
git clone https://github.com/themactep/streamripper.git
cd streamripper

# Create virtual environment and install package
uv venv
uv pip install -e .
```

#### Development Installation

```bash
git clone https://github.com/themactep/streamripper.git
cd streamripper

# Create virtual environment and install with development dependencies
uv venv
uv pip install -e ".[dev]"
```

#### Activate the virtual environment

```bash
# On Linux/macOS
source .venv/bin/activate

# On Windows
.venv\Scripts\activate
```

### Alternative Installation Methods

#### Using pip with venv

```bash
git clone https://github.com/themactep/streamripper.git
cd streamripper

# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install package
pip install -e .

# For development
pip install -e ".[dev]"
```

#### Using conda

```bash
git clone https://github.com/themactep/streamripper.git
cd streamripper

# Create and activate conda environment
conda create -n streamripper python=3.8
conda activate streamripper

# Install package
pip install -e .
```

#### Direct pip installation (not recommended for development)

```bash
git clone https://github.com/themactep/streamripper.git
cd streamripper
pip install -e .
```

## Usage

### Command Line Interface

```bash
# Analyze an RTSP stream for 30 seconds (default duration)
streamripper rtsp://example.com/stream

# Analyze an RTSP stream for 60 seconds
streamripper rtsp://example.com/stream --duration 60

# Analyze with custom output directory
streamripper rtsp://example.com/stream --output-dir ./my_analysis

# Enable debug logging
streamripper rtsp://example.com/stream --debug-log

# Generate combined chart showing both audio and video time drifts (default)
streamripper rtsp://example.com/stream --chart-type combined

# Generate separate charts for audio and video
streamripper rtsp://example.com/stream --duration 60 --chart-type separate

# Generate only video chart
streamripper rtsp://example.com/stream --duration 60 --chart-type video-only

# Generate comprehensive chart with all packets and separate drift lines
streamripper rtsp://example.com/stream --duration 60 --chart-type comprehensive

# Save the unaltered stream for further analysis
streamripper rtsp://example.com/stream --save-stream --duration 60

# Combine stream saving with analysis and charts
streamripper rtsp://example.com/stream --save-stream --debug-log --chart-type comprehensive
```

### Python API

```python
from streamripper import analyze_rtsp_stream, generate_combined_chart

# Analyze a stream
data = analyze_rtsp_stream(
    rtsp_url="rtsp://example.com/stream",
    duration=60,
    output_dir="./output",
    debug_log=True,
    timestamp_prefix="analysis",
    save_stream=True  # Save raw stream for further analysis
)

# Generate combined visualization showing both audio and video time drifts
generate_combined_chart(
    output_dir="./output",
    data=data,
    timestamp_prefix="analysis"
)
```

## Output

Streamripper generates several types of output:

1. **CSV Data File**: Detailed frame-by-frame analysis data
2. **Visual Charts**: PNG images with frame sizes and timing drift plots
   - **Combined Chart**: Shows both audio and video time drifts on the same plot (default)
   - **Comprehensive Chart**: Two-panel view with all packets (top) and separate drift lines (bottom)
   - **Separate Charts**: Individual charts for video and audio analysis
   - **Video-only Chart**: Focus on video stream analysis
   - **Audio-only Chart**: Focus on audio stream analysis
3. **Console Report**: Summary statistics and analysis results
4. **Debug Logs**: Detailed logging information (when enabled)
5. **Raw Bitstream File**: Unaltered H.264/H.265 bitstream (when `--save-stream` is used)

### Organized Output Structure

Streamripper automatically organizes outputs by stream source and run timestamp:

```
output/
└── 192_168_88_33_ch0/               # Sanitized URL directory (no protocol)
    └── 20231031_143022/             # Timestamp directory for this run
        ├── report.txt
        ├── flow.csv                 # Debug flow data (when --debug-log used)
        ├── chart_combined.png       # Analysis chart
        ├── stream.h264              # Raw H.264 bitstream (when --save-stream used)
        └── corruption.txt           # Corruption details (when --forensic used)
└── camera_example_com_554_stream/   # Another stream
    └── 20231031_150000/
        ├── report.txt
        ├── chart_combined.png
        └── stream.h265              # Raw H.265 bitstream
```

**Directory Naming:**
- Credentials are automatically removed from URLs
- Protocol prefix (rtsp://) is removed
- Non-alphanumeric characters become underscores
- `rtsp://user:pass@192.168.88.33/ch0` → `192_168_88_33_ch0/`
- `rtsp://camera.example.com:554/stream` → `camera_example_com_554_stream/`
- Each run creates a timestamped subdirectory for clean organization

## Configuration

### Environment Variables

- `STREAMRIPPER_OUTPUT_DIR`: Default output directory
- `STREAMRIPPER_DEBUG`: Enable debug logging by default

### Command Line Options

- `--duration`: Analysis duration in seconds (default: 30)
- `--output-dir`: Output directory for results (default: current directory)
- `--debug-log`: Enable detailed debug logging
- `--timestamp-prefix`: Custom prefix for output files
- `--chart-type`: Type of chart to generate (combined, comprehensive, separate, video-only, audio-only)
- `--no-chart`: Skip chart generation entirely
- `--save-stream`: Save the unaltered raw bitstream (H.264/H.265) for further analysis

## Development

### Setting up Development Environment

#### Recommended: Using uv

```bash
git clone https://github.com/themactep/streamripper.git
cd streamripper

# Create virtual environment and install development dependencies
uv venv
uv pip install -e ".[dev]"

# Activate virtual environment
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install pre-commit hooks
pre-commit install
```

#### Alternative: Using pip

```bash
git clone https://github.com/themactep/streamripper.git
cd streamripper

# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install development dependencies
pip install -r requirements-dev.txt
pre-commit install
```

### Running Tests

```bash
# Make sure your virtual environment is activated
pytest
```

### Code Formatting

```bash
# Make sure your virtual environment is activated
black src/ tests/
flake8 src/ tests/
mypy src/
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built with [PyAV](https://github.com/PyAV-Org/PyAV) for video processing
- Uses [matplotlib](https://matplotlib.org/) for visualization
- Data analysis powered by [pandas](https://pandas.pydata.org/)

## Support

For support, please open an issue on GitHub or contact the maintainer at paul@themactep.com.
