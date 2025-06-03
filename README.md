# Beyond Testing: Symbolic Execution Augmented Selection for LLM-Generated Code

**Submitted to ASE 2025**

This repository contains the code and data for our paper:  
**"Beyond Testing: Symbolic Execution Augmented Selection for LLM-Generated Code"**

Our method augments traditional test-based selection with **symbolic execution**, enabling stricter and more comprehensive correctness evaluation of LLM-generated code. We evaluate the approach across multiple benchmarks and research questions.

---

## 🔧 Project Structure

```
.
├── run.sh                     # Run the baseline test-based selection
├── run_exec.sh               # Run symbolic execution over generated code
├── main_execution.py         # Evaluate and compare different selection strategies
├── /data                     # Datasets and results for RQ1, RQ2, RQ3
```

---

## Quick Start

### Run symbolic execution

```bash
bash run_exec.sh
```

### Run selection

```bash
bash run.sh
```

### Evaluate selection strategies

```bash
python main_execution.py
```

---

## Data

All experiment data for RQ1, RQ2, and RQ3 are located in the `/data` folder.

---

## Dependencies

A partial list of Python packages used in this project:

- `angr==9.2.102`
- `claripy==9.2.102`
- `z3-solver==4.10.2.0`
- `archinfo==9.2.102`
- `cle==9.2.102`
- `pyvex==9.2.102`
- `PySMT==0.9.6`
- `datasets==3.1.0`
- `fire==0.7.0`
- `pandas==2.0.3`
- `matplotlib`
- `openai==1.57.3`
- `mxeval==1.0`
- `human-eval==1.0`
