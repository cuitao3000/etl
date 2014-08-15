package etl

import (
    "regexp"
    "strings"
    "encoding/json"
    "os"
    "io"
    "io/ioutil"
    "bytes"
    "log"
    "fmt"
    "path/filepath"
    "time"
    "sync"
    "bufio"
    "errors"
    "strconv"
)


type kvsChan chan map[string]string
type columnsMap map[string]map[string][]string   // {"type": {"columns":[] , "partitions":[]}, ...}

var LogKinds = []string{"access", "click", "open", "others"}

type Dispatcher struct {
    typeColsMap columnsMap
    writers map[string]io.WriteCloser
    outDir string
    routineNum int       //routine个数
    outFilePrefix string  //输出文件名的默认前缀
    mutex *sync.RWMutex
    typeValueRe *regexp.Regexp
    hostsRe []*regexp.Regexp  //合法host的正则
    ipBlackList map[uint32]int  //ip黑名单 
}

func NewDispatcher(colsMapFile string, outDir string, routineNum int, outFilePrefix string, hostsWhiteListFile string, ipBlackListFile string) *Dispatcher {
    m := loadColsMap(colsMapFile)
    w := make(map[string]io.WriteCloser)
    if routineNum < 0 {
        routineNum = 20
    }
    if outFilePrefix == "" {
        outFilePrefix = "etl"
    }
    mutex := &sync.RWMutex{}
    typeValueRe := regexp.MustCompile("^[0-9,a-z,A-Z,_]*$")
    hostsWhiteList := loadHostsWhiteList(hostsWhiteListFile)
    ipBlackList := loadIpBlackList(ipBlackListFile)
    return &Dispatcher{ m, w, outDir, routineNum, outFilePrefix, mutex, typeValueRe, hostsWhiteList, ipBlackList }
}

func loadColsMap(fname string) columnsMap {
    m := make(columnsMap)
    content , err := ioutil.ReadFile(fname)
    if err != nil {
        log.Println("read cols map file error", err)
    }else{
        err = json.Unmarshal(content, &m)
        if err != nil {
            log.Println("decode cols map error", err)
        }
    }
    return m
}

func loadHostsWhiteList(whiteListFile string) []*regexp.Regexp {
    wlist := make([]*regexp.Regexp, 0)

    fin, err := os.Open(whiteListFile)
    if err != nil {
        log.Println("load hosts white list:", whiteListFile, "error:", err)
    }else{
        scanner := bufio.NewScanner(fin)
        for scanner.Scan() {
            pat := scanner.Text()
            if pat != "" {
                re, err := regexp.Compile(pat)
                if err != nil {
                    log.Println("compile white list [" + pat + "] error:", err)
                }else{
                    wlist = append(wlist, re)
                }
            }else{
                log.Println("discard white list empty line")
            }
        }
        fin.Close()
    }
    log.Println("load host white list size:", len(wlist))
    return wlist
}

func loadIpBlackList(blackListFile string) map[uint32]int {
    blackList := make(map[uint32]int)

    fin, err := os.Open(blackListFile)
    if err != nil {
        log.Println("load ip black list:", blackListFile, "error:", err)
    }else{
        scanner := bufio.NewScanner(fin)
        for scanner.Scan() {
            line := strings.Trim(scanner.Text(), " ")
            if line[0] != '#' {
                ipl, err := ipToInt(line)
                if err != nil {
                    log.Println("trans black ip", line, "to int error:", err)
                }else{
                    blackList[ipl] = 1
                }
            }
        }
        fin.Close()
    }
    log.Println("load ip black list size:", len(blackList))
    return blackList
}
//先使用kvs的event_ipinlong检查，直接转成整型就能用
//如果这个key是空，再转event_ip
func (d *Dispatcher) isBlackIp(kvs map[string]string) bool {
    //如果black list为空，则所有ip都ok
    if len(d.ipBlackList) == 0 {
        return false
    }

    var ipl uint32
    var err error = errors.New("kvs had no ip key")

    iplStr, ok := kvs["event_ipinlong"]
    if ok && iplStr != "" {
        i, er := strconv.ParseUint(iplStr, 10, 32)
        err = er
        if er == nil {
            ipl = uint32(i)
        }else{
            log.Println("trans ipLong", iplStr, "to uint error", err)
        }
    }else if ip, ok := kvs["event_ip"]; ok {
        i, er := ipToInt(ip)
        err = er
        ipl = i
        if er != nil {
            log.Println("[check ip] trans", ip, "to long error:", err)
        }
    }
    _, ok = d.ipBlackList[ipl]
    return ok
}
func (d *Dispatcher) check_type_value(t string) bool {
    if len(t) > 20 {
        return false
    }
    return d.typeValueRe.MatchString(t)
}

func (d *Dispatcher) check_host_value(host string) bool {
    /*
    l := len(host)
    if l == 0 || l > 15 {
        return false
    }
    re := regexp.MustCompile(`^[a-z,A-Z,\.]{1,8}\.hao[12]2[23]\.com$`)
    return re.MatchString(host)
    */
    ret := false
    for _, re := range d.hostsRe {
        if re.MatchString(host) {
            ret = true
            break
        }
    }
    return ret
}

func (d *Dispatcher) check_url_path(path string) bool {
    return strings.LastIndex(path, ".") == -1 || strings.HasSuffix(path, ".html") || strings.HasSuffix(path, ".htm")
}

func (d *Dispatcher) Disp_global_hao123_access(globalhao123_type string, event_urlpath string, globalhao123_host string) bool {
    if !d.check_type_value(globalhao123_type) || !d.check_host_value(globalhao123_host) {
        return false
    }

    if event_urlpath == "/img/gut.gif" && ("access" == globalhao123_type || "faccess" == globalhao123_type) {
        return true
    }
    return false
}

func (d *Dispatcher) Disp_global_hao123_click(globalhao123_type string, event_urlpath string, globalhao123_host string) bool {
    if !d.check_type_value(globalhao123_type) || !d.check_host_value(globalhao123_host) {
        return false
    }

    if event_urlpath == "/img/gut.gif" && /*"" != globalhao123_type &&*/ "access" != globalhao123_type && "faccess" != globalhao123_type {
        return true
    }
    return false
}

func (d *Dispatcher) Disp_global_hao123_others(globalhao123_type string, event_urlpath string, globalhao123_host string) bool {
    if !d.check_type_value(globalhao123_type) || !d.check_host_value(globalhao123_host) {
        return false
    }

    if d.check_url_path(event_urlpath) && globalhao123_type != "bad_type" {
        return true
    }
    return false
}

func (d *Dispatcher) Disp_global_hao123_open(globalhao123_type string, event_urlpath string, globalhao123_host string) bool {
    if !d.check_type_value(globalhao123_type) || !d.check_host_value(globalhao123_host) {
        return false
    }

    if event_urlpath == "/img/open-gut.gif" {
        return true
    }
    return false
}

//清理过期的文件操作符
func (d *Dispatcher) closeWriters(all bool) {
    now := time.Now().Unix()
    var interval = int64(5 * 86400)

    re, _ := regexp.Compile(`/(\d{8})/`)
    for k, w := range d.writers {
        if all {
            w.Close()
            d.mutex.Lock()
            delete(d.writers, k)
            d.mutex.Unlock()
            continue
        }

        ret := re.FindSubmatch([]byte(k))
        if ret == nil {
            //格式不对，直接关闭
            w.Close()
            d.mutex.Lock()
            delete(d.writers, k)
            d.mutex.Unlock()
            log.Println("[wrong writer]", k)
        }else{
            date := string(ret[1])
            tm, err := time.Parse("20060102", date)
            if err != nil || (now - tm.Unix()) > interval {
                w.Close()
                d.mutex.Lock()
                delete(d.writers, k)
                d.mutex.Unlock()
                log.Println("[clear writer]", k)
            }
        }
    }
}

func (d *Dispatcher) writeFile(w io.WriteCloser, kvs map[string]string, kind string) {
    if w != nil {
        var ok bool
        cols, ok := d.typeColsMap[kind]["columns"]
        if !ok {
            log.Println("wrong log kind <", kind, "> when write file");
            return;
        }

        var buf bytes.Buffer
        var val string
        nCols := len(cols)

        for i, col := range cols {
            val = ""
            if col != "" {
                val, ok = kvs[col]
                if !ok {
                    log.Println(kind, "miss field:", col)
                }
            }
            //替换掉可能的换行符
            if val != "" {
                val = strings.Replace(val, "\n", "", -1)
            }
            buf.WriteString(val)
            if i != nCols - 1 {
                buf.WriteByte('\t')
            }
        }
        if buf.Len() > 0 {
            buf.WriteByte('\n')
            w.Write(buf.Bytes())
        }
    }
}

func (d *Dispatcher) makePartitionsPath(kvs map[string]string, partitions []string) string {
    tmp := make([]string, 0)
    for _, p := range partitions {
        v, ok := kvs[p]
        if !ok || v == "" {
            v = "NONE"
        }
        tmp = append(tmp, v)
    }
    return filepath.Join(tmp...)
}

func (d *Dispatcher) saveFile(kvs map[string]string, kind string, routineId int) {
    //目录结构：/输出目录/四个大类型/分区构成的目录
    partitions, ok := d.typeColsMap[kind]["partitions"]
    if !ok {
        return;
    }
    partitionPath := d.makePartitionsPath(kvs, partitions)
    path := filepath.Join(d.outDir, kind, partitionPath)
    filename := fmt.Sprintf("%s/%s_r%d", path, d.outFilePrefix, routineId)
    d.mutex.RLock()
    w, ok := d.writers[filename]   //查找有无打开的文件操作符，可以避免一些系统调用
    d.mutex.RUnlock()
    if !ok {
        //先检查有无目录
        if _,err := os.Stat(path); err != nil && os.IsNotExist(err) {
            os.MkdirAll(path, 0775)
        }   
        fout, err := os.OpenFile(filename, os.O_WRONLY | os.O_APPEND | os.O_CREATE, 0666)
        if err != nil {
            log.Println("open", filename, "file for write error", err)
            return
        }else{
            w = fout
            if w == nil {
                log.Println("[error] fout", filename, "is nil")
                return
            }
            d.mutex.Lock()
            d.writers[filename] = w
            d.mutex.Unlock()
        }
    }
    d.writeFile(w, kvs, kind)
}
//获取日志类别
func (d *Dispatcher) getKind(kvs map[string]string) string {
    tp, _ := kvs["globalhao123_type"]
    path, _ := kvs["event_urlpath"]
    host, _ := kvs["globalhao123_host"]

    kind := ""

    if d.Disp_global_hao123_access(tp, path, host) {
        kind = "access"
    }else if d.Disp_global_hao123_click(tp, path, host) {
        kind = "click"
    }else if d.Disp_global_hao123_open(tp, path, host) {
        kind = "open"
    }else if d.Disp_global_hao123_others(tp, path, host) {
        kind = "others"
    }
    return kind
}

func (d *Dispatcher) dispatchRoutine(ch kvsChan, wg *sync.WaitGroup, routineId int) {
    log.Println("start dispatch routine", routineId)
    for kvs := range ch {
        //过滤ip黑名单
        if d.isBlackIp(kvs) {
            continue
        }
        kind := d.getKind(kvs)
        if kind != "" {
            d.saveFile(kvs, kind, routineId)
        }
        //log.Println("out chan", routineId, len(ch))
    }
    wg.Done()   //ch 关闭后routine自动结束
    log.Println("close dispatch routine", routineId)
}
func (d *Dispatcher) Dispatch(ch kvsChan, quitCh chan int) {
    //定期清理文件操作符
    go func(){
        for {
            time.Sleep(2 * time.Hour)
            d.closeWriters(false)
        }
    }()
    wg := &sync.WaitGroup{}
    wg.Add(d.routineNum)
    for i:=0; i<d.routineNum; i++ {
        go d.dispatchRoutine(ch, wg, i)
    }

    wg.Wait()
    d.closeWriters(true)
    log.Println("dispatcher finish!")
    quitCh <- 1
} 
