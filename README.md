# PERUN ⚡

PERUN은 Linux x86_64 환경에서 Windows **PE32+ (64-bit AMD64)** 콘솔 실행 파일(.exe)을 직접 파싱하고, 가상 메모리 공간에 로딩하여 섹션 매핑, 메모리 페이지 보호 권한 설정, 그리고 재배치(Base Relocation)를 수행하는 경량 PE 로더 및 런타임 라이브러리입니다.

C99 표준 규격과 POSIX API만을 사용하여 작성되었으며, 메모리 경계 검사 및 리소스 해제 등의 예외 처리를 엄격히 설계하여 취약점을 제어하는 보안 중심(Security-Hardened)의 설계를 채택하고 있습니다.

---

## 🚀 주요 특징 (Key Features)

### 1. Phase 1 - PE 파일 무결성 및 구조 파싱 (PE Parser)
* **DOS Header 검증:** 파일의 시작 부분에서 `MZ (0x5A4D)` 매직넘버를 유효성 검사합니다.
* **NT Header 검증:** DOS 헤더 내부의 `e_lfanew` 오프셋 범위 유효성을 검사한 뒤 `PE\0\0 (0x00004550)` 시그니처를 검증합니다.
* **아키텍처 및 형식 식별:** 머신 타입이 `AMD64 (0x8664)`이고 Optional Header Magic이 `PE32+ (0x20b)` 포맷인지 체크하여 64비트 전용 로더의 스펙을 검증합니다.
* **섹션 경계 검사:** 파일 크기 대비 각 섹션 헤더 크기의 범위를 대조하여 조작된 PE 파일의 비정상적인 버퍼 접근을 사전에 예방합니다.

### 2. Phase 2 - 가상 메모리 매핑 및 페이지 권한 설정 (PE Loader)
* **메모리 할당:** PE 파일 내부에 기록된 `SizeOfImage` 크기에 따라 프로세스의 가상 메모리 공간을 `mmap`을 통해 예약합니다. (초기 복사 권한: `PROT_READ | PROT_WRITE`)
* **헤더 및 섹션 맵핑:** `SizeOfHeaders`에 명시된 만큼 헤더 데이터를 복사한 후, 각 섹션을 정렬 단위(RVA)에 맞춰 해당 주소로 개별 매핑합니다.
* **BSS 영역 초기화:** `VirtualSize`가 `SizeOfRawData`보다 큰 경우, 나머지 메모리 공간을 0으로 강제 초기화하여 미초기화 데이터(BSS) 공간을 구성합니다.
* **메모리 보호 권한 적용 (`mprotect`):** 모든 복사 및 재배치 조치가 끝난 직후, 각 섹션의 characteristics에 명시된 플래그(Read/Write/Execute)를 Linux 메모리 권한으로 변환합니다. `sysconf(_SC_PAGESIZE)`를 반영해 가상메모리 페이지 경계로 정렬된 주소 및 크기를 산정하여 `mprotect`를 안전하게 적용합니다.

### 3. Phase 3 - 재배치(Relocation) 핸들러 구현
* **재배치 델타(Delta) 연산:** 실제 로드된 메모리 기저 주소(`loaded_base`)와 PE 파일이 가정한 선호 기저 주소(`ImageBase`)의 차이를 산출합니다.
* **Base Relocation Directory 파싱:** `IMAGE_DIRECTORY_ENTRY_BASERELOC`를 역참조하여 4KB 가상메모리 페이지 단위의 재배치 블록(`IMAGE_BASE_RELOCATION`)들을 차례대로 파싱합니다.
* **64비트 주소 보정:** 16비트 오프셋 엔트리 배열에서 타입이 `IMAGE_REL_BASED_DIR64 (10)`인 지점을 식별하여, `delta` 값을 가산(add) 패치해 절대 주소 레퍼런스를 보정합니다.
* **아웃오브바운드(OOB) 메모리 보호:** 블록 크기의 정밀성 점검 및 보정 타겟 RVA의 전체 이미지 크기 범위 초과 여부를 사전 검사하여 안전성을 강화했습니다.

### 4. 보안 및 신뢰성 설계 (Security-Hardened Design)
* **포맷 스트링 취약점 원천 차단:** 에러 로깅 및 디버깅 출력부에서 외부 인자(`argv`)를 포맷 스트링 인자로 직접 전달하지 않고, 정적 포맷 지시자(Format specifier)를 적용해 설계되었습니다.
* **Use-After-Free (UAF) 방지:** 예외 발생에 따른 조기 리턴 및 최종 자원 해제 시점(`pe_loader_free` 및 `free(buffer)`) 직후 포인터를 즉시 `NULL`로 클리어해 댕글링 포인터를 활용한 공격 경로를 방단합니다.

---

## 📁 디렉토리 구조 (Directory Structure)

```text
PERUN/
├── CMakeLists.txt              # CMake 빌드 설정
├── README.md                   # 프로젝트 문서
├── .gitignore                  # Git 버전 관리 제외 설정
├── include/                    # 헤더 파일 디렉토리
│   ├── pe_format.h            # PE32+ 포맷 규격 구조체 및 상수 정의
│   ├── pe_parser.h            # PE 파서 데이터 구조 및 인터페이스
│   ├── pe_loader.h            # PE 로더/매핑/재배치 인터페이스
│   └── perun.h                # 공용 파서/로더 컨텍스트 구조
├── src/                        # 소스 코드 디렉토리
│   ├── main.c                 # 프로그램 진입점 및 실행 흐름 제어
│   ├── pe_parser.c            # PE 파서 구현부 (Phase 1)
│   └── pe_loader.c            # PE 로더/매핑/재배치 구현부 (Phase 2 & 3)
└── tests/                      # 테스트 도구 디렉토리
    ├── generate_dummy_pe.py   # 재배치 테스트를 위한 가짜 PE32+ 생성 스크립트
    └── dummy.exe              # 파이썬 스크립트로 생성된 테스트 이진 파일
```

---

## 🛠️ 빌드 방법 (Build Instructions)

`CMake`와 `make`가 설치된 Linux x86_64 환경에서 아래 명령어를 실행하여 빌드합니다.

```bash
# 1. 빌드 디렉토리 생성 및 이동
mkdir build
cd build

# 2. CMake 설정 생성
cmake ..

# 3. 컴파일 및 링킹 실행
make
```

빌드가 성공하면 `build/perun` 바이너리 파일이 생성됩니다.

---

## 🖥️ 사용 방법 (Usage)

### 1. PE 헤더 및 섹션 덤프 출력 모드 (`--info`)
이진 파일의 DOS/NT 헤더 주요 정보와 섹션 목록을 요약하여 출력합니다.
```bash
./build/perun --info tests/dummy.exe
```
*출력 예시:*
```text
Machine: x86_64
Format: PE32+
ImageBase: 0x140000000
EntryPoint RVA: 0x1000
Number of sections: 3

Sections:
.text    RVA=0x1000   RAW=0x200    SIZE=0x200   
.data    RVA=0x2000   RAW=0x400    SIZE=0x100   
.reloc   RVA=0x3000   RAW=0x600    SIZE=0x200   
```

### 2. 가상 메모리 로딩 및 재배치 수행 모드 (일반 실행)
PE 이미지 맵핑, BSS 패딩, 메모리 권한(RWX) 적용, 재배치 가산을 한 뒤 디버깅 결과를 출력합니다.
```bash
./build/perun tests/dummy.exe
```
*출력 예시:*
```text
Applying Relocation (Delta: 0x7a955e5ca000)...
Successfully applied relocations.
Successfully mapped and loaded PE in memory!
Allocated Base VA: 0x7a969e5ca000
SizeOfImage: 0x4000

Mapped Sections:
  .text    RVA=0x1000   -> Memory VA=0x7a969e5cb000 (Size=0x200   )
    -> [Debug] Value at .text+0x10 (relocated ptr): 0x7a969e5cc000 (expected to match .data VA)
  .data    RVA=0x2000   -> Memory VA=0x7a969e5cc000 (Size=0x100   )
  .reloc   RVA=0x3000   -> Memory VA=0x7a969e5cd000 (Size=0x200   )
```

---

## 📐 수학적 재배치 일치성 증명 (Mathematical Verification)

* **테스트 셋업:** 파이썬 스크립트(`generate_dummy_pe.py`)를 통해 `.text` 섹션의 시작부(`RVA 0x1000`)에 속한 `0x10` 오프셋에 **64비트 하드코딩 절대 주소 `0x140002000`**을 셋업합니다. (해당 값은 가상의 컴파일 ImageBase `0x140000000` + `.data` 섹션의 `RVA 0x2000`의 합성치입니다.)
* **프로세스 로드 및 델타 계산:** 리눅스 프로세스 내에서 mmap이 반환한 주소가 `0x7a969e5ca000` 일 때, 델타 주소는 다음과 같이 계산됩니다:
  $$\text{Delta} = 0x7a969e5ca000 - 0x140000000 = 0x7a955e5ca000$$
* **재배치 패치 수행:** 로더의 재배치 연산에 의해 해당 오프셋(`.text + 0x10`)의 주소값에 델타가 가산됩니다:
  $$\text{Patched Value} = 0x140002000 + 0x7a955e5ca000 = 0x7a969e5cc000$$
* **검증:** 보정된 메모리 값(`0x7a969e5cc000`)은 실제 메모리에 매핑된 `.data` 섹션의 시작 주소(`Memory VA = 0x7a969e5cc000`)와 완벽하게 일치합니다. 이를 통해 가상 메모리 매핑 및 재배치 테이블 탐색 연산이 한 바이트의 오차도 없이 완전히 작동함을 증명했습니다.
