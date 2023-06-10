class Counter:
    count = 0  # 类级别的属性

    def increment(self):
        self.__class__.count += 1

    def get_count(self):
        return self.__class__.count

# 创建两个 Counter 实例
c1 = Counter()
c2 = Counter()

# 递增计数器
print(c1.count)
c1.increment()
c2.increment()
c2.increment()

# 获取计数器的值
print(c1.get_count())  # 输出: 3
print(c2.get_count())  # 输出: 3